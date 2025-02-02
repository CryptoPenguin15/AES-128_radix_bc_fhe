use tfhe::shortint::Ciphertext;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::prelude::ServerKeyDefaultCMux;
use tfhe::integer::{BooleanBlock, RadixClientKey, ServerKey};

use std::collections::HashMap;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rayon::prelude::*;

const PS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

pub struct PosVals {
    p_b: [BaseRadixCiphertext<Ciphertext>; 8],
    v_0: BaseRadixCiphertext<Ciphertext>,
}

impl PosVals {
    pub fn new(ck: &RadixClientKey) -> Self {
        let p_b = core::array::from_fn(|i| ck.encrypt(PS[i]));
        let v_0 = ck.encrypt(0u8);
        PosVals { p_b, v_0 }
    }

    #[inline]
    pub fn get_p_b(&self) -> &[BaseRadixCiphertext<Ciphertext>; 8] {
        &self.p_b
    }

    #[inline]
    pub fn get_v_0(&self) -> &BaseRadixCiphertext<Ciphertext> {
        &self.v_0
    }
}

pub struct ColBoolBlocks {
    r1: [BooleanBlock; 8],
    r2: [BooleanBlock; 8],
    r3: [BooleanBlock; 8],
    r4: [BooleanBlock; 8],
}

impl ColBoolBlocks {
    pub fn new(values: [[BooleanBlock; 8]; 4]) -> Self {
        Self {
            r1: values[0].clone(),
            r2: values[1].clone(),
            r3: values[2].clone(),
            r4: values[3].clone(),
        }
    }
}

#[inline]
fn get_bool_from_u8(
    idx: &BaseRadixCiphertext<Ciphertext>,
    pos_vals: &PosVals,
    sk: &ServerKey,
) -> [BooleanBlock; 8] {
    let p_b = pos_vals.get_p_b();

    let x_p: Vec<BooleanBlock> = (0..8)
        .into_par_iter()
        .map(|i| {
            let mask = sk.bitand_parallelized(&p_b[i], idx);
            sk.eq_parallelized(&mask, &p_b[i])
        })
        .collect();

    x_p.try_into()
        .unwrap_or_else(|_| panic!("Failed to convert Vec to array"))
}

#[inline]
fn get_u8_from_bool(
    res_p: [BooleanBlock; 8],
    pos_vals: &PosVals,
    sk: &ServerKey,
) -> BaseRadixCiphertext<Ciphertext> {
    let p_b = pos_vals.get_p_b();
    let v_0 = pos_vals.get_v_0();

    let r_b: Vec<BaseRadixCiphertext<Ciphertext>> = (0..8)
        .into_par_iter()
        .map(|i| sk.if_then_else_parallelized(&res_p[i], &p_b[i], v_0))
        .collect();

    r_b.into_par_iter()
        .reduce(|| v_0.clone(), |a, b| sk.bitor_parallelized(&a, &b))
}

#[inline]
pub fn sbox_idx(
    idx: &BaseRadixCiphertext<Ciphertext>,
    pos_vals: &PosVals,
    sk: &ServerKey,
) -> BaseRadixCiphertext<Ciphertext> {
    let x_p = get_bool_from_u8(idx, pos_vals, sk);
    let res_p = sbox_bc(&x_p, sk);

    get_u8_from_bool(res_p, pos_vals, sk)
}

#[inline]
pub fn mix_cols(
    col: &[BaseRadixCiphertext<Ciphertext>; 4],
    pos_vals: &PosVals,
    sk: &ServerKey,
) -> [BaseRadixCiphertext<Ciphertext>; 4] {
    let r1_p = get_bool_from_u8(&col[0], pos_vals, sk);
    let r2_p = get_bool_from_u8(&col[1], pos_vals, sk);
    let r3_p = get_bool_from_u8(&col[2], pos_vals, sk);
    let r4_p = get_bool_from_u8(&col[3], pos_vals, sk);

    let inp = ColBoolBlocks::new([r1_p, r2_p, r3_p, r4_p]);
    let res_p = mix_cols_bc(&inp, sk);

    let out1 = get_u8_from_bool(res_p.r1, pos_vals, sk);
    let out2 = get_u8_from_bool(res_p.r2, pos_vals, sk);
    let out3 = get_u8_from_bool(res_p.r3, pos_vals, sk);
    let out4 = get_u8_from_bool(res_p.r4, pos_vals, sk);

    [out1, out2, out3, out4]
}

#[inline]
pub fn sbox_inv_idx(
    idx: &BaseRadixCiphertext<Ciphertext>,
    pos_vals: &PosVals,
    sk: &ServerKey,
) -> BaseRadixCiphertext<Ciphertext> {
    let x_p = get_bool_from_u8(idx, pos_vals, sk);
    let res_p = sbox_inv_bc(&x_p, sk);

    get_u8_from_bool(res_p, pos_vals, sk)
}

#[inline]
fn sbox_bc(inp: &[BooleanBlock; 8], sk: &ServerKey) -> [BooleanBlock; 8] {
    let map = HashMap::<String, BooleanBlock>::new();
    let var = Arc::new(Mutex::new(map));

    // reverse order
    for i in 0..=7 {
        var.lock()
            .unwrap()
            .insert(format!("x{}", i), inp[7 - i].clone());
    }

    let vlen = SBOX_INSTR.len();
    let idx = &AtomicI32::new(0);

    thread::scope(|s| {
        for _ in 0..std::cmp::min(8, num_cpus::get()) {
            let sk_clone = sk.clone();
            let instr_clone = SBOX_INSTR;
            let var_clone = var.clone();

            s.spawn(move || {
                loop {
                    let b = idx.fetch_add(1, Relaxed);
                    if b >= vlen.try_into().unwrap() {
                        break;
                    }

                    let st = instr_clone.get(b as usize).unwrap();
                    let tokens = st.split(' ').collect::<Vec<_>>();

                    let op = tokens[3];
                    let name = tokens[0];

                    let value = match op {
                        "^" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[2]) && var2.contains_key(tokens[4])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[2]].clone();
                            let t1 = &var2[tokens[4]].clone();
                            drop(var2);
                            sk_clone.boolean_bitxor(t0, t1)
                        }
                        "&" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[2]) && var2.contains_key(tokens[4])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[2]].clone();
                            let t1 = &var2[tokens[4]].clone();
                            drop(var2);
                            sk_clone.boolean_bitand(t0, t1)
                        }
                        "!" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[2])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[2]].clone();
                            drop(var2);
                            sk_clone.boolean_bitnot(t0)
                        }
                        &_ => todo!(),
                    };
                    let mut var2 = var_clone.lock().unwrap();
                    var2.insert(name.to_string(), value);
                }
            });
        }
    });

    // reverse order
    let out: [BooleanBlock; 8] = (0..8)
        .map(|i| {
            var.lock()
                .unwrap()
                .get(&format!("s{}", 7 - i))
                .cloned()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    out.clone()
}

/*
#[inline]
fn sbox_bc(inp: &[BooleanBlock; 8], sk: &ServerKey) -> [BooleanBlock; 8] {
    // reverse order
    let x0 = &inp[7];
    let x1 = &inp[6];
    let x2 = &inp[5];
    let x3 = &inp[4];
    let x4 = &inp[3];
    let x5 = &inp[2];
    let x6 = &inp[1];
    let x7 = &inp[0];

    let y14 = sk.boolean_bitxor(x3, x5);
    let y13 = sk.boolean_bitxor(x0, x6);
    let y9 = sk.boolean_bitxor(x0, x3);
    let y8 = sk.boolean_bitxor(x0, x5);
    let t0 = sk.boolean_bitxor(x1, x2);
    let y1 = sk.boolean_bitxor(&t0, x7);
    let y4 = sk.boolean_bitxor(&y1, x3);
    let y12 = sk.boolean_bitxor(&y13, &y14);
    let y2 = sk.boolean_bitxor(&y1, x0);
    let y5 = sk.boolean_bitxor(&y1, x6);
    let y3 = sk.boolean_bitxor(&y5, &y8);
    let t1 = sk.boolean_bitxor(x4, &y12);
    let y15 = sk.boolean_bitxor(&t1, x5);
    let y20 = sk.boolean_bitxor(&t1, x1);
    let y6 = sk.boolean_bitxor(&y15, x7);
    let y10 = sk.boolean_bitxor(&y15, &t0);
    let y11 = sk.boolean_bitxor(&y20, &y9);
    let y7 = sk.boolean_bitxor(x7, &y11);
    let y17 = sk.boolean_bitxor(&y10, &y11);
    let y19 = sk.boolean_bitxor(&y10, &y8);
    let y16 = sk.boolean_bitxor(&t0, &y11);
    let y21 = sk.boolean_bitxor(&y13, &y16);
    let y18 = sk.boolean_bitxor(x0, &y16);

    let t2 = sk.boolean_bitand(&y12, &y15);
    let t3 = sk.boolean_bitand(&y3, &y6);
    let t4 = sk.boolean_bitxor(&t3, &t2);
    let t5 = sk.boolean_bitand(&y4, x7);
    let t6 = sk.boolean_bitxor(&t5, &t2);
    let t7 = sk.boolean_bitand(&y13, &y16);
    let t8 = sk.boolean_bitand(&y5, &y1);
    let t9 = sk.boolean_bitxor(&t8, &t7);
    let t10 = sk.boolean_bitand(&y2, &y7);
    let t11 = sk.boolean_bitxor(&t10, &t7);
    let t12 = sk.boolean_bitand(&y9, &y11);
    let t13 = sk.boolean_bitand(&y14, &y17);
    let t14 = sk.boolean_bitxor(&t13, &t12);
    let t15 = sk.boolean_bitand(&y8, &y10);
    let t16 = sk.boolean_bitxor(&t15, &t12);
    let t17 = sk.boolean_bitxor(&t4, &t14);
    let t18 = sk.boolean_bitxor(&t6, &t16);
    let t19 = sk.boolean_bitxor(&t9, &t14);
    let t20 = sk.boolean_bitxor(&t11, &t16);
    let t21 = sk.boolean_bitxor(&t17, &y20);
    let t22 = sk.boolean_bitxor(&t18, &y19);
    let t23 = sk.boolean_bitxor(&t19, &y21);
    let t24 = sk.boolean_bitxor(&t20, &y18);
    let t25 = sk.boolean_bitxor(&t21, &t22);
    let t26 = sk.boolean_bitand(&t21, &t23);
    let t27 = sk.boolean_bitxor(&t24, &t26);
    let t28 = sk.boolean_bitand(&t25, &t27);
    let t29 = sk.boolean_bitxor(&t28, &t22);
    let t30 = sk.boolean_bitxor(&t23, &t24);
    let t31 = sk.boolean_bitxor(&t22, &t26);
    let t32 = sk.boolean_bitand(&t31, &t30);
    let t33 = sk.boolean_bitxor(&t32, &t24);
    let t34 = sk.boolean_bitxor(&t23, &t33);
    let t35 = sk.boolean_bitxor(&t27, &t33);
    let t36 = sk.boolean_bitand(&t24, &t35);
    let t37 = sk.boolean_bitxor(&t36, &t34);
    let t38 = sk.boolean_bitxor(&t27, &t36);
    let t39 = sk.boolean_bitand(&t29, &t38);
    let t40 = sk.boolean_bitxor(&t25, &t39);
    let t41 = sk.boolean_bitxor(&t40, &t37);
    let t42 = sk.boolean_bitxor(&t29, &t33);
    let t43 = sk.boolean_bitxor(&t29, &t40);
    let t44 = sk.boolean_bitxor(&t33, &t37);
    let t45 = sk.boolean_bitxor(&t42, &t41);

    let z0 = sk.boolean_bitand(&t44, &y15);
    let z1 = sk.boolean_bitand(&t37, &y6);
    let z2 = sk.boolean_bitand(&t33, x7);
    let z3 = sk.boolean_bitand(&t43, &y16);
    let z4 = sk.boolean_bitand(&t40, &y1);
    let z5 = sk.boolean_bitand(&t29, &y7);
    let z6 = sk.boolean_bitand(&t42, &y11);
    let z7 = sk.boolean_bitand(&t45, &y17);
    let z8 = sk.boolean_bitand(&t41, &y10);
    let z9 = sk.boolean_bitand(&t44, &y12);
    let z10 = sk.boolean_bitand(&t37, &y3);
    let z11 = sk.boolean_bitand(&t33, &y4);
    let z12 = sk.boolean_bitand(&t43, &y13);
    let z13 = sk.boolean_bitand(&t40, &y5);
    let z14 = sk.boolean_bitand(&t29, &y2);
    let z15 = sk.boolean_bitand(&t42, &y9);
    let z16 = sk.boolean_bitand(&t45, &y14);
    let z17 = sk.boolean_bitand(&t41, &y8);

    let t46 = sk.boolean_bitxor(&z15, &z16);
    let t47 = sk.boolean_bitxor(&z10, &z11);
    let t48 = sk.boolean_bitxor(&z5, &z13);
    let t49 = sk.boolean_bitxor(&z9, &z10);
    let t50 = sk.boolean_bitxor(&z2, &z12);
    let t51 = sk.boolean_bitxor(&z2, &z5);
    let t52 = sk.boolean_bitxor(&z7, &z8);
    let t53 = sk.boolean_bitxor(&z0, &z3);
    let t54 = sk.boolean_bitxor(&z6, &z7);
    let t55 = sk.boolean_bitxor(&z16, &z17);
    let t56 = sk.boolean_bitxor(&z12, &t48);
    let t57 = sk.boolean_bitxor(&t50, &t53);
    let t58 = sk.boolean_bitxor(&z4, &t46);
    let t59 = sk.boolean_bitxor(&z3, &t54);
    let t60 = sk.boolean_bitxor(&t46, &t57);
    let t61 = sk.boolean_bitxor(&z14, &t57);
    let t62 = sk.boolean_bitxor(&t52, &t58);
    let t63 = sk.boolean_bitxor(&t49, &t58);
    let t64 = sk.boolean_bitxor(&z4, &t59);
    let t65 = sk.boolean_bitxor(&t61, &t62);
    let t66 = sk.boolean_bitxor(&z1, &t63);
    let t67 = sk.boolean_bitxor(&t64, &t65);

    let s7 = sk.boolean_bitnot(&sk.boolean_bitxor(&t48, &t60));
    let s6 = sk.boolean_bitnot(&sk.boolean_bitxor(&t56, &t62));
    let s5 = sk.boolean_bitxor(&t47, &t65);
    let s4 = sk.boolean_bitxor(&t51, &t66);
    let s3 = sk.boolean_bitxor(&t53, &t66);
    let s2 = sk.boolean_bitnot(&sk.boolean_bitxor(&t55, &t67));
    let s1 = sk.boolean_bitnot(&sk.boolean_bitxor(&t64, &s3));
    let s0 = sk.boolean_bitxor(&t59, &t63);

    // reverse order
    let out: [BooleanBlock; 8] = [s7, s6, s5, s4, s3, s2, s1, s0];

    out.clone()
}
*/

#[inline]
fn sbox_inv_bc(inp: &[BooleanBlock; 8], sk: &ServerKey) -> [BooleanBlock; 8] {
    // reverse order
    let u0 = &inp[7];
    let u1 = &inp[6];
    let u2 = &inp[5];
    let u3 = &inp[4];
    let u4 = &inp[3];
    let u5 = &inp[2];
    let u6 = &inp[1];
    let u7 = &inp[0];

    let y0 = sk.boolean_bitxor(u0, u3);
    let y2 = sk.boolean_bitnot(&sk.boolean_bitxor(u1, u3));
    let y4 = sk.boolean_bitxor(u0, &y2);
    let rtl0 = sk.boolean_bitxor(u6, u7);
    let y1 = sk.boolean_bitxor(&y2, &rtl0);
    let y7 = sk.boolean_bitnot(&sk.boolean_bitxor(u2, &y1));
    let rtl1 = sk.boolean_bitxor(u3, u4);
    let y6 = sk.boolean_bitnot(&sk.boolean_bitxor(u7, &rtl1));
    let y3 = sk.boolean_bitxor(&y1, &rtl1);
    let rtl2 = sk.boolean_bitnot(&sk.boolean_bitxor(u0, u2));
    let y5 = sk.boolean_bitxor(u5, &rtl2);
    let sa1 = sk.boolean_bitxor(&y0, &y2);
    let sa0 = sk.boolean_bitxor(&y1, &y3);
    let sb1 = sk.boolean_bitxor(&y4, &y6);
    let sb0 = sk.boolean_bitxor(&y5, &y7);
    let ah = sk.boolean_bitxor(&y0, &y1);
    let al = sk.boolean_bitxor(&y2, &y3);
    let aa = sk.boolean_bitxor(&sa0, &sa1);
    let bh = sk.boolean_bitxor(&y4, &y5);
    let bl = sk.boolean_bitxor(&y6, &y7);
    let bb = sk.boolean_bitxor(&sb0, &sb1);
    let ab20 = sk.boolean_bitxor(&sa0, &sb0);
    let ab22 = sk.boolean_bitxor(&al, &bl);
    let ab23 = sk.boolean_bitxor(&y3, &y7);
    let ab21 = sk.boolean_bitxor(&sa1, &sb1);
    let abcd1 = sk.boolean_bitand(&ah, &bh);
    let rr1 = sk.boolean_bitand(&y0, &y4);
    let ph11 = sk.boolean_bitxor(&ab20, &abcd1);
    let t01 = sk.boolean_bitand(&y1, &y5);
    let ph01 = sk.boolean_bitxor(&t01, &abcd1);
    let abcd2 = sk.boolean_bitand(&al, &bl);
    let r1 = sk.boolean_bitand(&y2, &y6);
    let pl11 = sk.boolean_bitxor(&ab22, &abcd2);
    let r2 = sk.boolean_bitand(&y3, &y7);
    let pl01 = sk.boolean_bitxor(&r2, &abcd2);
    let r3 = sk.boolean_bitand(&sa0, &sb0);
    let vr1 = sk.boolean_bitand(&aa, &bb);
    let pr1 = sk.boolean_bitxor(&vr1, &r3);
    let wr1 = sk.boolean_bitand(&sa1, &sb1);
    let qr1 = sk.boolean_bitxor(&wr1, &r3);
    let ab0 = sk.boolean_bitxor(&ph11, &rr1);
    let ab1 = sk.boolean_bitxor(&ph01, &ab21);
    let ab2 = sk.boolean_bitxor(&pl11, &r1);
    let ab3 = sk.boolean_bitxor(&pl01, &qr1);
    let cp1 = sk.boolean_bitxor(&ab0, &pr1);
    let cp2 = sk.boolean_bitxor(&ab1, &qr1);
    let cp3 = sk.boolean_bitxor(&ab2, &pr1);
    let cp4 = sk.boolean_bitxor(&ab3, &ab23);
    let tinv1 = sk.boolean_bitxor(&cp3, &cp4);
    let tinv2 = sk.boolean_bitand(&cp3, &cp1);
    let tinv3 = sk.boolean_bitxor(&cp2, &tinv2);
    let tinv4 = sk.boolean_bitxor(&cp1, &cp2);
    let tinv5 = sk.boolean_bitxor(&cp4, &tinv2);
    let tinv6 = sk.boolean_bitand(&tinv5, &tinv4);
    let tinv7 = sk.boolean_bitand(&tinv3, &tinv1);
    let d2 = sk.boolean_bitxor(&cp4, &tinv7);
    let d0 = sk.boolean_bitxor(&cp2, &tinv6);
    let tinv8 = sk.boolean_bitand(&cp1, &cp4);
    let tinv9 = sk.boolean_bitand(&tinv4, &tinv8);
    let tinv10 = sk.boolean_bitxor(&tinv4, &tinv2);
    let d1 = sk.boolean_bitxor(&tinv9, &tinv10);
    let tinv11 = sk.boolean_bitand(&cp2, &cp3);
    let tinv12 = sk.boolean_bitand(&tinv1, &tinv11);
    let tinv13 = sk.boolean_bitxor(&tinv1, &tinv2);
    let d3 = sk.boolean_bitxor(&tinv12, &tinv13);
    let sd1 = sk.boolean_bitxor(&d1, &d3);
    let sd0 = sk.boolean_bitxor(&d0, &d2);
    let dl = sk.boolean_bitxor(&d0, &d1);
    let dh = sk.boolean_bitxor(&d2, &d3);
    let dd = sk.boolean_bitxor(&sd0, &sd1);
    let abcd3 = sk.boolean_bitand(&dh, &bh);
    let rr2 = sk.boolean_bitand(&d3, &y4);
    let t02 = sk.boolean_bitand(&d2, &y5);
    let abcd4 = sk.boolean_bitand(&dl, &bl);
    let r4 = sk.boolean_bitand(&d1, &y6);
    let r5 = sk.boolean_bitand(&d0, &y7);
    let r6 = sk.boolean_bitand(&sd0, &sb0);
    let vr2 = sk.boolean_bitand(&dd, &bb);
    let wr2 = sk.boolean_bitand(&sd1, &sb1);
    let abcd5 = sk.boolean_bitand(&dh, &ah);
    let r7 = sk.boolean_bitand(&d3, &y0);
    let r8 = sk.boolean_bitand(&d2, &y1);
    let abcd6 = sk.boolean_bitand(&dl, &al);
    let r9 = sk.boolean_bitand(&d1, &y2);
    let r10 = sk.boolean_bitand(&d0, &y3);
    let r11 = sk.boolean_bitand(&sd0, &sa0);
    let vr3 = sk.boolean_bitand(&dd, &aa);
    let wr3 = sk.boolean_bitand(&sd1, &sa1);
    let ph12 = sk.boolean_bitxor(&rr2, &abcd3);
    let ph02 = sk.boolean_bitxor(&t02, &abcd3);
    let pl12 = sk.boolean_bitxor(&r4, &abcd4);
    let pl02 = sk.boolean_bitxor(&r5, &abcd4);
    let pr2 = sk.boolean_bitxor(&vr2, &r6);
    let qr2 = sk.boolean_bitxor(&wr2, &r6);
    let p0 = sk.boolean_bitxor(&ph12, &pr2);
    let p1 = sk.boolean_bitxor(&ph02, &qr2);
    let p2 = sk.boolean_bitxor(&pl12, &pr2);
    let p3 = sk.boolean_bitxor(&pl02, &qr2);
    let ph13 = sk.boolean_bitxor(&r7, &abcd5);
    let ph03 = sk.boolean_bitxor(&r8, &abcd5);
    let pl13 = sk.boolean_bitxor(&r9, &abcd6);
    let pl03 = sk.boolean_bitxor(&r10, &abcd6);
    let pr3 = sk.boolean_bitxor(&vr3, &r11);
    let qr3 = sk.boolean_bitxor(&wr3, &r11);
    let p4 = sk.boolean_bitxor(&ph13, &pr3);
    let s7 = sk.boolean_bitxor(&ph03, &qr3);
    let p6 = sk.boolean_bitxor(&pl13, &pr3);
    let p7 = sk.boolean_bitxor(&pl03, &qr3);
    let s3 = sk.boolean_bitxor(&p1, &p6);
    let s6 = sk.boolean_bitxor(&p2, &p6);
    let s0 = sk.boolean_bitxor(&p3, &p6);
    let x11 = sk.boolean_bitxor(&p0, &p2);
    let s5 = sk.boolean_bitxor(&s0, &x11);
    let x13 = sk.boolean_bitxor(&p4, &p7);
    let x14 = sk.boolean_bitxor(&x11, &x13);
    let s1 = sk.boolean_bitxor(&s3, &x14);
    let x16 = sk.boolean_bitxor(&p1, &s7);
    let s2 = sk.boolean_bitxor(&x14, &x16);
    let x18 = sk.boolean_bitxor(&p0, &p4);
    let x19 = sk.boolean_bitxor(&s5, &x16);
    let s4 = sk.boolean_bitxor(&x18, &x19);

    // reverse order
    let out: [BooleanBlock; 8] = [s7, s6, s5, s4, s3, s2, s1, s0];

    out.clone()
}

#[inline]
fn mix_cols_bc(col: &ColBoolBlocks, sk: &ServerKey) -> ColBoolBlocks {
    let map = HashMap::<String, BooleanBlock>::new();
    let var = Arc::new(Mutex::new(map));

    for i in 0..=7 {
        var.lock()
            .unwrap()
            .insert(format!("x{}", i), col.r1[i].clone());
    }

    for i in 0..=7 {
        var.lock()
            .unwrap()
            .insert(format!("x{}", i + 8), col.r2[i].clone());
    }

    for i in 0..=7 {
        var.lock()
            .unwrap()
            .insert(format!("x{}", i + 16), col.r3[i].clone());
    }

    for i in 0..=7 {
        var.lock()
            .unwrap()
            .insert(format!("x{}", i + 24), col.r4[i].clone());
    }

    let vlen = MIX_COLS_INSTR.len();
    let idx = &AtomicI32::new(0);

    thread::scope(|s| {
        for _ in 0..std::cmp::min(8, num_cpus::get()) {
            let sk_clone = sk.clone();
            let instr_clone = MIX_COLS_INSTR;
            let var_clone = var.clone();

            s.spawn(move || {
                loop {
                    let b = idx.fetch_add(1, Relaxed);
                    if b >= vlen.try_into().unwrap() {
                        break;
                    }
                    let st = instr_clone.get(b as usize).unwrap();
                    let tokens = st.split(' ').collect::<Vec<_>>();

                    let op = tokens[3];
                    let name = tokens[0];

                    let value = match op {
                        "^" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[2]) && var2.contains_key(tokens[4])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[2]].clone();
                            let t1 = &var2[tokens[4]].clone();
                            drop(var2);
                            sk_clone.boolean_bitxor(t0, t1)
                        }
                        &_ => todo!(),
                    };
                    let mut var2 = var_clone.lock().unwrap();
                    var2.insert(name.to_string(), value);
                }
            });
        }
    });

    let r1: [BooleanBlock; 8] = (0..8)
        .map(|i| {
            var.lock()
                .unwrap()
                .get(&format!("y{}", i))
                .cloned()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let r2: [BooleanBlock; 8] = (0..8)
        .map(|i| {
            var.lock()
                .unwrap()
                .get(&format!("y{}", i + 8))
                .cloned()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let r3: [BooleanBlock; 8] = (0..8)
        .map(|i| {
            var.lock()
                .unwrap()
                .get(&format!("y{}", i + 16))
                .cloned()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let r4: [BooleanBlock; 8] = (0..8)
        .map(|i| {
            var.lock()
                .unwrap()
                .get(&format!("y{}", i + 24))
                .cloned()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    ColBoolBlocks::new([r1, r2, r3, r4])
}

// https://eprint.iacr.org/2009/191.pdf
const SBOX_INSTR: [&str; 119] = [
    "y14 = x3 ^ x5",
    "y13 = x0 ^ x6",
    "y9 = x0 ^ x3",
    "y8 = x0 ^ x5",
    "t0 = x1 ^ x2",
    "y1 = t0 ^ x7",
    "y4 = y1 ^ x3",
    "y12 = y13 ^ y14",
    "y2 = y1 ^ x0",
    "y5 = y1 ^ x6",
    "y3 = y5 ^ y8",
    "t1 = x4 ^ y12",
    "y15 = t1 ^ x5",
    "y20 = t1 ^ x1",
    "y6 = y15 ^ x7",
    "y10 = y15 ^ t0",
    "y11 = y20 ^ y9",
    "y7 = x7 ^ y11",
    "y17 = y10 ^ y11",
    "y19 = y10 ^ y8",
    "y16 = t0 ^ y11",
    "y21 = y13 ^ y16",
    "y18 = x0 ^ y16",
    "t2 = y12 & y15",
    "t3 = y3 & y6",
    "t4 = t3 ^ t2",
    "t5 = y4 & x7",
    "t6 = t5 ^ t2",
    "t7 = y13 & y16",
    "t8 = y5 & y1",
    "t9 = t8 ^ t7",
    "t10 = y2 & y7",
    "t11 = t10 ^ t7",
    "t12 = y9 & y11",
    "t13 = y14 & y17",
    "t14 = t13 ^ t12",
    "t15 = y8 & y10",
    "t16 = t15 ^ t12",
    "t17 = t4 ^ t14",
    "t18 = t6 ^ t16",
    "t19 = t9 ^ t14",
    "t20 = t11 ^ t16",
    "t21 = t17 ^ y20",
    "t22 = t18 ^ y19",
    "t23 = t19 ^ y21",
    "t24 = t20 ^ y18",
    "t25 = t21 ^ t22",
    "t26 = t21 & t23",
    "t27 = t24 ^ t26",
    "t28 = t25 & t27",
    "t29 = t28 ^ t22",
    "t30 = t23 ^ t24",
    "t31 = t22 ^ t26",
    "t32 = t31 & t30",
    "t33 = t32 ^ t24",
    "t34 = t23 ^ t33",
    "t35 = t27 ^ t33",
    "t36 = t24 & t35",
    "t37 = t36 ^ t34",
    "t38 = t27 ^ t36",
    "t39 = t29 & t38",
    "t40 = t25 ^ t39",
    "t41 = t40 ^ t37",
    "t42 = t29 ^ t33",
    "t43 = t29 ^ t40",
    "t44 = t33 ^ t37",
    "t45 = t42 ^ t41",
    "z0 = t44 & y15",
    "z1 = t37 & y6",
    "z2 = t33 & x7",
    "z3 = t43 & y16",
    "z4 = t40 & y1",
    "z5 = t29 & y7",
    "z6 = t42 & y11",
    "z7 = t45 & y17",
    "z8 = t41 & y10",
    "z9 = t44 & y12",
    "z10 = t37 & y3",
    "z11 = t33 & y4",
    "z12 = t43 & y13",
    "z13 = t40 & y5",
    "z14 = t29 & y2",
    "z15 = t42 & y9",
    "z16 = t45 & y14",
    "z17 = t41 & y8",
    "t46 = z15 ^ z16",
    "t47 = z10 ^ z11",
    "t48 = z5 ^ z13",
    "t49 = z9 ^ z10",
    "t50 = z2 ^ z12",
    "t51 = z2 ^ z5",
    "t52 = z7 ^ z8",
    "t53 = z0 ^ z3",
    "t54 = z6 ^ z7",
    "t55 = z16 ^ z17",
    "t56 = z12 ^ t48",
    "t57 = t50 ^ t53",
    "t58 = z4 ^ t46",
    "t59 = z3 ^ t54",
    "t60 = t46 ^ t57",
    "t61 = z14 ^ t57",
    "t62 = t52 ^ t58",
    "t63 = t49 ^ t58",
    "t64 = z4 ^ t59",
    "t65 = t61 ^ t62",
    "t66 = z1 ^ t63",
    "t67 = t64 ^ t65",
    "s77 = t48 ^ t60",
    "s7 = s77 !",
    "s66 = t56 ^ t62",
    "s6 = s66 !",
    "s5 = t47 ^ t65",
    "s4 = t51 ^ t66",
    "s3 = t53 ^ t66",
    "s22 = t55 ^ t67",
    "s2 = s22 !",
    "s11 = t64 ^ s3",
    "s1 = s11 !",
    "s0 = t59 ^ t63",
];

// https://eprint.iacr.org/2019/833.pdf
const MIX_COLS_INSTR: [&str; 92] = [
    "t0 = x0 ^ x8",
    "t1 = x16 ^ x24",
    "t2 = x1 ^ x9",
    "t3 = x17 ^ x25",
    "t4 = x2 ^ x10",
    "t5 = x18 ^ x26",
    "t6 = x3 ^ x11",
    "t7 = x19 ^ x27",
    "t8 = x4 ^ x12",
    "t9 = x20 ^ x28",
    "t10 = x5 ^ x13",
    "t11 = x21 ^ x29",
    "t12 = x6 ^ x14",
    "t13 = x22 ^ x30",
    "t14 = x23 ^ x31",
    "t15 = x7 ^ x15",
    "t16 = x8 ^ t1",
    "y0 = t15 ^ t16",
    "t17 = x7 ^ x23",
    "t18 = x24 ^ t0",
    "y16 = t14 ^ t18",
    "t19 = t1 ^ y16",
    "y24 = t17 ^ t19",
    "t20 = x27 ^ t14",
    "t21 = t0 ^ y0",
    "y8 = t17 ^ t21",
    "t22 = t5 ^ t20",
    "y19 = t6 ^ t22",
    "t23 = x11 ^ t15",
    "t24 = t7 ^ t23",
    "y3 = t4 ^ t24",
    "t25 = x2 ^ x18",
    "t26 = t17 ^ t25",
    "t27 = t9 ^ t23",
    "t28 = t8 ^ t20",
    "t29 = x10 ^ t2",
    "y2 = t5 ^ t29",
    "t30 = x26 ^ t3",
    "y18 = t4 ^ t30",
    "t31 = x9 ^ x25",
    "t32 = t25 ^ t31",
    "y10 = t30 ^ t32",
    "y26 = t29 ^ t32",
    "t33 = x1 ^ t18",
    "t34 = x30 ^ t11",
    "y22 = t12 ^ t34",
    "t35 = x14 ^ t13",
    "y6 = t10 ^ t35",
    "t36 = x5 ^ x21",
    "t37 = x30 ^ t17",
    "t38 = x17 ^ t16",
    "t39 = x13 ^ t8",
    "y5 = t11 ^ t39",
    "t40 = x12 ^ t36",
    "t41 = x29 ^ t9",
    "y21 = t10 ^ t41",
    "t42 = x28 ^ t40",
    "y13 = t41 ^ t42",
    "y29 = t39 ^ t42",
    "t43 = x15 ^ t12",
    "y7 = t14 ^ t43",
    "t44 = x14 ^ t37",
    "y31 = t43 ^ t44",
    "t45 = x31 ^ t13",
    "y15 = t44 ^ t45",
    "y23 = t15 ^ t45",
    "t46 = t12 ^ t36",
    "y14 = y6 ^ t46",
    "t47 = t31 ^ t33",
    "y17 = t19 ^ t47",
    "t48 = t6 ^ y3",
    "y11 = t26 ^ t48",
    "t49 = t2 ^ t38",
    "y25 = y24 ^ t49",
    "t50 = t7 ^ y19",
    "y27 = t26 ^ t50",
    "t51 = x22 ^ t46",
    "y30 = t11 ^ t51",
    "t52 = x19 ^ t28",
    "y20 = x28 ^ t52",
    "t53 = x3 ^ t27",
    "y4 = x12 ^ t53",
    "t54 = t3 ^ t33",
    "y9 = y8 ^ t54",
    "t55 = t21 ^ t31",
    "y1 = t38 ^ t55",
    "t56 = x4 ^ t17",
    "t57 = x19 ^ t56",
    "y12 = t27 ^ t57",
    "t58 = x3 ^ t28",
    "t59 = t17 ^ t58",
    "y28 = x20 ^ t59",
];

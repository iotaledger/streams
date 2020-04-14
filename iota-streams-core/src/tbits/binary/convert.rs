use super::defs::*;
use crate::tbits::{
    convert::{
        log2e3,
        ConvertOnto,
    },
    trinary::Trit,
    TbitSlice,
    TbitSliceMut,
};

impl ConvertOnto<Trit> for Byte {
    fn cvt_onto(from: TbitSlice<Byte>, onto: &mut TbitSliceMut<Trit>) {
        assert!(onto.size() < 10000);
        let b = log2e3(onto.size() as u64) as usize;
        assert!(from.size() > b);

        // Reserve (b+1)-bit integer.
        let mut integer = vec![0_u32; (b + 32) / 32];
        let integer_slice = TbitSliceMut::<Byte>::from_raw_ptr(b + 1, integer.as_mut_ptr() as *mut Byte);
        from.take(b + 1).copy(&integer_slice);

        while !onto.is_empty() {
            // carry = integer % 3
            // integer = integer / 3
            //TODO: use larger base, eg. 243: div integer mod 243 and convert rem into chunks of 5 trits.
            let mut carry = 0_u32;
            for n in integer.iter_mut().rev() {
                let v = ((carry as u64) << 32) + (*n as u64);
                carry = (v % 3) as u32;
                *n = (v / 3) as u32;
            }

            onto.advance(1).put_trit(Trit(carry as u8));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbits::{
        binary::Byte,
        Tbits,
    };

    #[test]
    fn convert_onto_trit() {
        let bytes = Tbits::<Byte>::from_tbits(&[Bit(1); 250 * 8 / 5]);
        let mut trits = Tbits::<Trit>::zero(250);

        let mut test = |n_trits, trit_str| {
            <Byte as ConvertOnto<Trit>>::cvt_onto(
                bytes.slice().take(log2e3(n_trits as u64) as usize + 1),
                &mut trits.slice_mut().take(n_trits),
            );
            assert!(trits.slice().take(n_trits).eq_str(trit_str));
        };

        test(1, "9");
        test(2, "X");
        test(3, "D");
        test(4, "SA");
        test(5, "L9");
        test(40, "OVUUFXVJFEWOKA");
        test(80, "AWRCFGOSE9QCPELEFZH9GCAWSIA");
        test(120, "VZZDERMFOQXLXUHDRSSEWVYLAGFQCQAPUW9CDXDQ");
    }
}

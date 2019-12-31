/*
 * Copyright (c) 2019 c-mnd
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#![allow(dead_code)]

use std::fmt;

use crate::trits::{Trit};

pub const NUM_ROUNDS: usize = 24;
pub const TROIKA_RATE: usize = 243;

const COLUMNS: usize = 9;
const ROWS: usize = 3;
const SLICES: usize = 27;
const SLICESIZE: usize = COLUMNS * ROWS;
const STATE_SIZE: usize = COLUMNS * ROWS * SLICES;

#[derive(Clone, Copy)]
struct T27(pub u32, pub u32);

impl fmt::Debug for T27 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "T27: [{},{}]", self.0, self.1,)
    }
}

impl T27 {
    fn new(p: u32, n: u32) -> T27 {
        T27(p, n)
    }
    //#[inline]
    fn clean(&self) -> T27 {
        T27::new(self.0 & 0x07ffffffu32, self.1 & 0x07ffffffu32)
    }
    //#[inline]
    fn add(&self, other: &T27) -> T27 {
        let self_zero: u32 = !(self.0 | self.1);
        let p = !((self.1 ^ other.1) | (self_zero ^ other.0));
        let n = !((self.0 ^ other.0) | (self_zero ^ other.1));
        T27::new(p, n)
    }
    //#[inline]
    fn mul(&self, other: &T27) -> T27 {
        let p = (self.0 & other.0) | (self.1 & other.1);
        let n = (self.0 & other.1) | (self.1 & other.0);
        T27::new(p, n)
    }
    //#[inline]
    fn zero() -> T27 {
        T27::new(0, 0)
    }
    //#[inline]
    fn one() -> T27 {
        T27::new(0x07ffffffu32, 0)
    }
    //#[inline]
    fn minus() -> T27 {
        T27::new(0, 0x07ffffffu32)
    }
    //#[inline]
    fn dec(&self) -> T27 {
        T27::minus().add(&self)
    }
    //#[inline]
    fn inc(&self) -> T27 {
        T27::one().add(&self)
    }
    //#[inline]
    fn set(&mut self, pos: usize, value: Trit) {
        let mask: u32 = 1u32 << pos;
        self.0 &= !mask;
        self.1 &= !mask;
        match value {
            1 => self.0 |= mask,
            2 => self.1 |= mask,
            _ => (),
        }
    }
    //#[inline]
    fn get(&self, pos: usize) -> Trit {
        let mask: u32 = 1u32 << pos;
        if self.0 & mask != 0 {
            return 1;
        } else if self.1 & mask != 0 {
            return 2;
        }
        0
    }
    //#[inline]
    fn roll(&self, by: usize) -> T27 {
        let p = ((self.0 << by) | (self.0 >> (27 - by))) & 0x07ffffff;
        let n = ((self.1 << by) | (self.1 >> (27 - by))) & 0x07ffffff;
        T27::new(p, n)
    }
}

const FROUND_CONSTANTS: [[T27; COLUMNS]; NUM_ROUNDS] = [
    [
        T27(119734530, 1610953),
        T27(5749794, 34095441),
        T27(8585540, 55080601),
        T27(37884008, 77409799),
        T27(54010117, 84576),
        T27(1516630, 113295913),
        T27(67149892, 28728632),
        T27(18946819, 46269656),
        T27(71707578, 53494784),
    ],
    [
        T27(16777439, 103161856),
        T27(106015553, 10769436),
        T27(21266449, 11549090),
        T27(25182214, 106707976),
        T27(3511622, 21651481),
        T27(99250704, 98573),
        T27(86049024, 8946816),
        T27(115430790, 18522649),
        T27(34802142, 90448384),
    ],
    [
        T27(52954114, 4518880),
        T27(42049594, 69225857),
        T27(64652, 119014242),
        T27(2361764, 79725587),
        T27(11788385, 71306002),
        T27(104925460, 18936387),
        T27(126091277, 7368848),
        T27(50448421, 76157720),
        T27(8389632, 69472985),
    ],
    [
        T27(5267465, 119801412),
        T27(219376, 96215813),
        T27(69452824, 31209699),
        T27(2458688, 26900536),
        T27(9216196, 23217449),
        T27(9479304, 84560389),
        T27(14721540, 118622586),
        T27(18134123, 33751056),
        T27(17839280, 8454144),
    ],
    [
        T27(50535754, 83100304),
        T27(77465099, 56709376),
        T27(3229283, 54835588),
        T27(111780009, 4473088),
        T27(78153311, 1384832),
        T27(2200712, 85617187),
        T27(3410924, 71341072),
        T27(75661345, 34434134),
        T27(56763059, 69011456),
    ],
    [
        T27(111543554, 1650793),
        T27(16908812, 37251073),
        T27(104910882, 1517085),
        T27(26041368, 103842404),
        T27(48022528, 2229055),
        T27(54104125, 71320960),
        T27(35722818, 93087928),
        T27(84559900, 3190850),
        T27(27582482, 37816716),
    ],
    [
        T27(68786250, 54928432),
        T27(3686682, 63278693),
        T27(70045, 100557312),
        T27(38150276, 94408058),
        T27(46798629, 2394242),
        T27(1202190, 8988112),
        T27(34308201, 94384916),
        T27(17518227, 3145772),
        T27(973329, 136),
    ],
    [
        T27(56633740, 8765490),
        T27(68419770, 749061),
        T27(100942913, 23267584),
        T27(79923980, 51667986),
        T27(41853745, 25172098),
        T27(39327896, 75776000),
        T27(44671808, 68175902),
        T27(2245138, 13929772),
        T27(33650945, 79037966),
    ],
    [
        T27(270473, 90363412),
        T27(72887432, 25346582),
        T27(100829319, 16593224),
        T27(40087630, 68684337),
        T27(6369457, 110496512),
        T27(4784407, 25472000),
        T27(33891012, 79219770),
        T27(53838530, 8936492),
        T27(68643936, 525057),
    ],
    [
        T27(102302534, 16841864),
        T27(50364433, 75530210),
        T27(84025378, 41014464),
        T27(25225495, 102827176),
        T27(4194888, 1050917),
        T27(84026756, 39440496),
        T27(2102125, 76284930),
        T27(219, 101056512),
        T27(100738441, 5820436),
    ],
    [
        T27(10228162, 67365944),
        T27(5235808, 8393488),
        T27(51989651, 2228780),
        T27(16847505, 76433508),
        T27(67651608, 33591874),
        T27(69017778, 35784448),
        T27(33587208, 76568885),
        T27(117440518, 4257472),
        T27(96273297, 154690),
    ],
    [
        T27(124317824, 1508111),
        T27(34873472, 98616918),
        T27(111182400, 1330494),
        T27(69374511, 54871056),
        T27(27626369, 38929480),
        T27(37879972, 26052698),
        T27(71587392, 44040194),
        T27(14000288, 2101064),
        T27(35672064, 97980170),
    ],
    [
        T27(81296, 47317509),
        T27(38469910, 25472072),
        T27(29738560, 36700214),
        T27(3267745, 117973262),
        T27(97993472, 528537),
        T27(84567940, 13731898),
        T27(77335148, 21041296),
        T27(51463726, 6724033),
        T27(1116193, 23601996),
    ],
    [
        T27(80396928, 18153737),
        T27(117581700, 10059826),
        T27(21505356, 101124275),
        T27(23679023, 42993616),
        T27(103681057, 4268108),
        T27(72885098, 18914433),
        T27(97846858, 2627621),
        T27(8422144, 104538235),
        T27(83948099, 40176916),
    ],
    [
        T27(6928902, 67256433),
        T27(67184746, 41588096),
        T27(69355878, 38529),
        T27(41473220, 67313922),
        T27(50647688, 4336995),
        T27(92288643, 248148),
        T27(12134919, 37884008),
        T27(35146408, 2601044),
        T27(9423489, 17835048),
    ],
    [
        T27(68231686, 6477024),
        T27(57284529, 8398852),
        T27(69316740, 34996770),
        T27(33696260, 24642995),
        T27(46333986, 85212492),
        T27(54665779, 12422144),
        T27(47791116, 311458),
        T27(44671584, 72368411),
        T27(2773762, 29428924),
    ],
    [
        T27(70976736, 62972703),
        T27(123864709, 10004498),
        T27(4202128, 11157861),
        T27(4859922, 61129797),
        T27(43331726, 69782577),
        T27(83935362, 49559848),
        T27(18875398, 1355904),
        T27(34433676, 78808178),
        T27(106038508, 27888147),
    ],
    [
        T27(4627260, 33570944),
        T27(4538630, 121155721),
        T27(9245346, 117613917),
        T27(33571009, 29853970),
        T27(2392559, 43652096),
        T27(93343744, 37793194),
        T27(17309712, 36148998),
        T27(3276900, 118312456),
        T27(101315856, 5638796),
    ],
    [
        T27(1587272, 132514822),
        T27(4229205, 77297034),
        T27(5767570, 84216428),
        T27(110247047, 21528952),
        T27(125878920, 7743841),
        T27(42033186, 73801480),
        T27(8388866, 2699881),
        T27(127159080, 2240724),
        T27(17324188, 112468544),
    ],
    [
        T27(34341913, 91345154),
        T27(105251840, 2623560),
        T27(4798982, 10634481),
        T27(39389184, 84174433),
        T27(88113152, 8667000),
        T27(34284722, 329),
        T27(39360568, 67200132),
        T27(6844996, 58720546),
        T27(104799233, 29368426),
    ],
    [
        T27(51429916, 80362691),
        T27(88855204, 262411),
        T27(8655522, 71558228),
        T27(17838342, 11076784),
        T27(92751916, 1577424),
        T27(33559104, 8931338),
        T27(1055746, 99418513),
        T27(85018341, 39885072),
        T27(63800, 120587968),
    ],
    [
        T27(5517104, 84070467),
        T27(118067364, 5522242),
        T27(39922643, 68435980),
        T27(73796250, 35144996),
        T27(2528811, 37838868),
        T27(37880008, 17144593),
        T27(21317458, 112754688),
        T27(113268098, 20677181),
        T27(2597136, 47730886),
    ],
    [
        T27(68438280, 50397942),
        T27(59853500, 68030786),
        T27(1475096, 41965991),
        T27(85852370, 37775145),
        T27(1071361, 44113962),
        T27(68040205, 62931234),
        T27(5847109, 78005290),
        T27(34465024, 12720668),
        T27(71860611, 44513824),
    ],
    [
        T27(109057155, 3197812),
        T27(2396909, 16843778),
        T27(67383952, 31605828),
        T27(70387369, 37875732),
        T27(119275955, 28228),
        T27(34079753, 73679286),
        T27(50603056, 71422530),
        T27(10385546, 86017108),
        T27(227426, 12060561),
    ],
];

#[derive(Clone, Copy)]
pub struct Troika {
    state: [T27; SLICESIZE], //TODO: use [[T27; 3]; 9]? or [[T27; 9]; 3]?
}

impl Troika {
    //#[inline]
    pub fn new() -> Self {
        Troika::default()
    }

    fn state(&self) -> &[T27] {
        &self.state
    }

    //#[inline]
    fn zeroize(&mut self) {
        let mask = 0x07fffe00u32;
        for i in 0..SLICESIZE {
            self.state[i].0 &= mask;
            self.state[i].1 &= mask;
        }
    }

    //#[inline]
    pub fn set1(&mut self, idx: usize, trit: Trit) {
        self.state[idx % SLICESIZE].set(idx / SLICESIZE, trit);
    }
    //#[inline]
    pub fn get1(&self, idx: usize) -> Trit {
        self.state[idx % SLICESIZE].get(idx / SLICESIZE)
    }
    //#[inline]
    fn set(&mut self, idx: usize, trits: &[Trit]) {
        //assert!(idx + trits.len() < RATE);
        let mut i = idx;
        for t in trits.iter() {
            self.set1(i, *t);
            i += 1;
        }
    }
    //#[inline]
    fn get(&self, idx: usize, trits: &mut [Trit]) {
        //assert!(self.avail() >= trits.len());
        let mut i = idx;
        for t in trits.iter_mut() {
            *t = self.get1(i);
            i += 1;
        }
    }

    //#[inline]
    pub fn permutation(&mut self) {
        for round in 0..NUM_ROUNDS {
            self.sub_trytes();
            self.shift_rows();
            self.shift_lanes();
            self.add_column_parity();
            self.add_round_constant(round);
        }
    }
    //#[inline]
    fn sub_tryte(a: &mut [T27]) {
        let d = a[0].dec();
        let e = d.mul(&a[1]).add(&a[2]);
        let f = e.mul(&a[1]).add(&d);
        let g = e.mul(&f).add(&a[1]);
        a[2] = e.clean();
        a[1] = f.clean();
        a[0] = g.clean();
    }
    //#[inline]
    fn sub_trytes(&mut self) {
        for rowcol in (0..SLICESIZE).step_by(3) {
            Troika::sub_tryte(&mut self.state[rowcol..(rowcol + 3)]);
        }
    }
    //#[inline]
    fn swap3(&mut self, a: usize, b: usize, c: usize) {
        let t = self.state[a];
        self.state[a] = self.state[b];
        self.state[b] = self.state[c];
        self.state[c] = t;
    }
    //#[inline]
    fn shift_rows(&mut self) {
        self.swap3(12, 9, 15);
        self.swap3(13, 10, 16);
        self.swap3(14, 11, 17);

        self.swap3(24, 18, 21);
        self.swap3(25, 19, 22);
        self.swap3(26, 20, 23);
    }
    //#[inline]
    fn shift_lanes(&mut self) {
        const SHIFTS: [u8; 27] = [
            19, 13, 21, 10, 24, 15, 2, 9, 3, 14, 0, 6, 5, 1, 25, 22, 23, 20, 7, 17, 26, 12, 8, 18,
            16, 11, 4,
        ];
        for i in 0..SLICESIZE {
            self.state[i as usize] = self.state[i].roll(SHIFTS[i] as usize);
        }
    }

    //#[inline]
    fn add_column_parity(&mut self) {
        let mut parity = [T27::zero(); COLUMNS];
        for col in 0..COLUMNS {
            let mut col_sum = T27::zero();
            for row in 0..ROWS {
                col_sum = col_sum.add(&self.state[COLUMNS * row + col]);
            }
            parity[col] = col_sum;
        }
        for row in 0..ROWS {
            for col in 0..COLUMNS {
                let idx = COLUMNS * row + col;
                let t1 = parity[if col == 0 { COLUMNS - 1 } else { col - 1 }];
                let t2 = parity[if col == COLUMNS - 1 { 0 } else { col + 1 }].roll(SLICES - 1);
                let sum_to_add = t1.add(&t2);
                self.state[idx] = self.state[idx].add(&sum_to_add);
            }
        }
    }

    //#[inline]
    fn add_round_constant(&mut self, round: usize) {
        for col in 0..COLUMNS {
            let round_const = FROUND_CONSTANTS[round][col];
            self.state[col] = self.state[col].add(&round_const);
        }
    }
}

impl Default for Troika {
    fn default() -> Troika {
        Troika {
            state: [T27::zero(); SLICESIZE],
        }
    }
}

impl fmt::Debug for Troika {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Troika: {:?}",
            self.state,
        )
    }
}

/// The TroikaSponge struct is a Sponge that uses the Troika permutation.
///
/// # Example
///
/// ```rust
/// extern crate iota_mam;
/// use iota_mam::troika::TroikaSponge;
/// // Create an array of 243 1s
/// let input = [1; 243];
/// // Create an array of 243 0s
/// let mut out = [0; 243];
/// let mut ftroika = TroikaSponge::default();
/// ftroika.absorb(&input);
/// ftroika.finalize();
/// ftroika.squeeze(&mut out);
/// ```
pub struct TroikaSponge {
    transform: Troika,
    rate: usize,
    index: usize,
}

impl Default for TroikaSponge {
    fn default() -> TroikaSponge {
        TroikaSponge {
            transform: Troika::default(),
            rate: 243,
            index: 0,
        }
    }
}

impl TroikaSponge {
    //#[inline]
    pub fn reset(&mut self) {
        self.transform.state = [T27::zero(); SLICESIZE];
        self.index = 0;
    }

    fn avail(&self) -> usize {
        self.rate - self.index
    }

    pub fn absorb(&mut self, trits: &[Trit]) {
        let mut length = trits.len();
        let mut trit_idx = 0;
        while length > 0 {
            if self.index == 0 {
                self.transform.zeroize();
            }
            let space = std::cmp::min(length, self.avail());
            self.transform.set(self.index, &trits[trit_idx..trit_idx + space]);
            self.index += space;
            length -= space;
            trit_idx += space;
            if self.index == self.rate {
                self.transform.permutation();
                self.index = 0;
            }
        }
    }
    pub fn finalize(&mut self) {
        let pad: [Trit; 1] = [1];
        self.absorb(&pad);
        if self.index != 0 {
            self.transform.permutation();
            self.index = 0;
        }
    }

    pub fn squeeze(&mut self, trits: &mut [Trit]) {
        let mut length = trits.len();
        let mut trit_idx = 0;
        while length > 0 {
            let space = std::cmp::min(length, self.avail());
            self.transform.get(self.index, &mut trits[trit_idx .. trit_idx + space]);
            self.index += space;
            trit_idx += space;
            length -= space;
            if self.avail() == 0 {
                self.transform.permutation();
                self.index = 0;
            }
        }
    }

}

#[cfg(test)]
mod test {
    use super::*;

    const HASH: [u8; 243] = [
        0, 2, 2, 1, 2, 1, 0, 1, 2, 1, 1, 1, 1, 2, 2, 1, 1, 1, 0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 2,
        1, 1, 1, 0, 1, 0, 2, 1, 0, 0, 0, 1, 2, 0, 2, 1, 0, 0, 2, 1, 1, 1, 1, 1, 2, 0, 1, 0, 2, 1,
        1, 2, 0, 1, 1, 1, 1, 1, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 1, 2, 2, 0, 2, 1, 1, 2, 1,
        1, 1, 2, 2, 1, 1, 0, 0, 0, 2, 2, 2, 0, 2, 1, 1, 1, 1, 0, 0, 1, 0, 2, 0, 2, 0, 2, 0, 0, 0,
        0, 1, 1, 1, 0, 2, 1, 1, 1, 0, 2, 0, 0, 1, 0, 1, 0, 2, 0, 2, 2, 0, 0, 2, 2, 0, 1, 2, 1, 0,
        0, 1, 2, 1, 1, 0, 0, 1, 1, 0, 2, 1, 1, 0, 1, 2, 0, 0, 0, 1, 2, 2, 1, 1, 1, 0, 0, 2, 0, 1,
        1, 2, 1, 1, 2, 1, 0, 1, 2, 2, 2, 2, 1, 2, 0, 2, 2, 1, 2, 1, 2, 1, 2, 2, 1, 1, 2, 0, 2, 1,
        0, 1, 1, 1, 0, 2, 2, 0, 0, 2, 0, 2, 0, 1, 2, 0, 0, 2, 2, 1, 1, 2, 0, 1, 0, 0, 0, 0, 2, 0,
        2, 2, 2,
    ];

    #[test]
    fn hash() {
        let mut ftroika = TroikaSponge::default();
        let mut output = [0u8; 243];
        let input = [0u8; 243];
        ftroika.absorb(&input);
        ftroika.finalize();
        ftroika.squeeze(&mut output);

        assert!(
            output.iter().zip(HASH.iter()).all(|(a, b)| a == b),
            "Arrays are not equal"
        );
    }

    #[test]
    fn stdtest1() {
        let input = [0u8; 1];
        const HASH: [u8; 243] = [
            0, 0, 2, 0, 0, 0, 2, 0, 2, 1, 0, 2, 2, 2, 0, 2, 0, 1, 0, 0, 1, 2, 2, 0, 1, 1, 1, 
            0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 2, 2, 2, 1, 1, 2, 2, 1, 1, 0, 2, 1, 
            1, 0, 0, 2, 1, 1, 0, 1, 2, 0, 2, 1, 0, 1, 1, 0, 1, 1, 0, 1, 2, 0, 1, 0, 1, 2, 0, 
            1, 2, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 1, 0, 0, 2, 2, 1, 1, 1, 0, 2, 0, 2, 2, 1, 2, 
            0, 0, 1, 2, 2, 2, 1, 0, 2, 0, 2, 0, 2, 1, 0, 0, 2, 0, 0, 0, 2, 0, 1, 2, 2, 0, 0, 
            2, 1, 1, 2, 2, 0, 0, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 0, 1, 0, 1, 0, 2, 0, 1, 2, 2, 
            1, 2, 0, 0, 0, 1, 0, 1, 1, 2, 0, 1, 0, 1, 0, 2, 1, 1, 2, 0, 0, 2, 1, 0, 0, 2, 1, 
            0, 2, 0, 0, 0, 0, 0, 2, 1, 0, 0, 1, 2, 0, 2, 0, 0, 1, 1, 2, 2, 0, 0, 2, 2, 1, 0, 
            2, 2, 1, 1, 1, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 1, 2, 1, 2, 2, 2, 2, 0, 0, 0, 2,
        ];
        let mut ftroika = TroikaSponge::default();
        let mut output = [0u8; 243];
        ftroika.absorb(&input);
        ftroika.finalize();
        ftroika.squeeze(&mut output);

        assert!(
            output.iter().zip(HASH.iter()).all(|(a, b)| a == b),
            "Arrays are not equal"
        );
    }

    #[test]
    fn stdtest2() {
        let input = [0u8; 2];
        const HASH: [u8; 243] = [
            2, 0, 2, 0, 0, 2, 1, 1, 1, 1, 1, 0, 1, 2, 0, 0, 1, 1, 1, 0, 1, 2, 2, 1, 2, 2, 2, 
            1, 2, 0, 0, 2, 2, 1, 1, 1, 0, 1, 2, 2, 0, 1, 2, 0, 2, 1, 2, 1, 2, 1, 2, 0, 1, 0, 
            0, 0, 0, 0, 1, 0, 2, 0, 2, 0, 2, 1, 2, 2, 2, 0, 1, 0, 2, 1, 2, 1, 2, 1, 2, 1, 0, 
            2, 1, 0, 2, 0, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 0, 1, 0, 0, 0, 2, 1, 0, 0, 1, 2, 1, 
            1, 1, 0, 0, 0, 1, 1, 2, 1, 2, 1, 2, 0, 0, 0, 2, 2, 2, 1, 2, 1, 2, 0, 2, 0, 0, 2, 
            2, 1, 0, 0, 0, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 1, 0, 0, 2, 2, 1, 0, 1, 2, 1, 1, 
            2, 0, 0, 1, 1, 1, 2, 1, 2, 1, 0, 2, 2, 0, 1, 1, 2, 0, 2, 2, 1, 1, 0, 2, 1, 1, 2, 
            0, 2, 0, 0, 1, 1, 1, 0, 2, 0, 0, 0, 0, 2, 1, 0, 1, 2, 2, 1, 1, 0, 2, 2, 2, 1, 1, 
            0, 0, 2, 1, 1, 2, 2, 0, 0, 2, 1, 2, 0, 1, 2, 2, 1, 1, 2, 0, 2, 2, 1, 2, 1, 1, 1, 
        ];
        let mut ftroika = TroikaSponge::default();
        let mut output = [0u8; 243];
        ftroika.absorb(&input);
        ftroika.finalize();
        ftroika.squeeze(&mut output);

        assert!(
            output.iter().zip(HASH.iter()).all(|(a, b)| a == b),
            "Arrays are not equal"
        );
    }

    #[test]
    fn stdtest3() {
        let mut input = [0u8; 243];
        input[0] = 1u8;
        input[242] = 2u8;
        const HASH: [u8; 243] = [
            1, 2, 0, 2, 2, 0, 1, 2, 1, 2, 1, 2, 0, 2, 0, 2, 1, 1, 0, 1, 2, 2, 0, 2, 2, 2, 1, 
            1, 2, 1, 2, 1, 2, 2, 2, 1, 2, 1, 1, 0, 2, 2, 1, 1, 2, 2, 2, 2, 2, 0, 1, 2, 1, 2, 
            0, 0, 1, 2, 2, 1, 0, 1, 1, 2, 0, 2, 2, 1, 1, 0, 2, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 
            1, 0, 0, 0, 1, 2, 0, 2, 1, 2, 2, 2, 0, 1, 1, 2, 1, 1, 1, 1, 1, 2, 0, 2, 2, 1, 0, 
            1, 0, 2, 2, 0, 2, 2, 1, 1, 1, 2, 0, 1, 0, 2, 2, 1, 1, 2, 2, 2, 0, 0, 0, 0, 0, 2, 
            2, 1, 0, 2, 0, 2, 1, 2, 1, 0, 0, 1, 2, 2, 1, 0, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 1, 
            0, 2, 1, 0, 1, 0, 0, 0, 0, 0, 2, 1, 2, 2, 1, 0, 1, 1, 2, 2, 0, 0, 0, 2, 1, 0, 0, 
            0, 1, 2, 2, 2, 1, 0, 2, 0, 0, 1, 0, 1, 1, 2, 0, 0, 1, 2, 2, 2, 0, 2, 0, 1, 1, 2, 
            1, 0, 0, 2, 1, 1, 0, 2, 0, 2, 2, 1, 1, 2, 1, 1, 0, 1, 1, 0, 1, 1, 0, 2, 2, 1, 2, 
        ];
        let mut ftroika = TroikaSponge::default();
        let mut output = [0u8; 243];
        ftroika.absorb(&input);
        ftroika.finalize();
        ftroika.squeeze(&mut output);

        assert!(
            output.iter().zip(HASH.iter()).all(|(a, b)| a == b),
            "Arrays are not equal"
        );
    }
}

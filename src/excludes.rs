const BLACKROCK_SEED: u64 = 0xdeadbeef101dd;
const BLACKROCK_ROUNDS: usize = 14; // https://github.com/robertdavidgraham/masscan/blob/9065684c52682d3e12a35559ef72cd0f07838bff/src/main.c#L1588

use perfect_rand::PerfectRng;
use std::{cmp, net::Ipv4Addr};

#[derive(Debug)]
/// IPs to be excluded from a scan
pub enum ExcludedIps {
    Cidr(Ipv4Addr, u8),
    Range(Ipv4Addr, Ipv4Addr),
    Address(Ipv4Addr),
}

#[derive(Debug, Clone, Copy)]
/// Inclusive range, start always <= end
pub struct Range {
    pub start: u32,
    pub end: u32,
}

impl IntoIterator for Range {
    type Item = u32;
    type IntoIter = RangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        let rng = PerfectRng::new(
            (self.end - self.start) as u64 + 1,
            BLACKROCK_SEED,
            BLACKROCK_ROUNDS,
        );

        RangeIterator {
            next: self.start as u64,
            end: self.end as u64,
            rng,
        }
    }
}

#[derive(Debug)]
/// Iterator over a a range of IPs, randomized order
pub struct RangeIterator {
    next: u64,
    end: u64,
    rng: PerfectRng,
}

impl Iterator for RangeIterator {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next;
        if current > self.end {
            return None;
        }

        self.next += 1;
        Some(self.rng.shuffle(current) as u32)
    }
}

impl ExcludedIps {
    /// Convert excluded IPs to a range of IPs
    pub fn to_range(&self) -> Range {
        match *self {
            ExcludedIps::Cidr(ip, mask) => {
                let mask = (1 << (32 - mask)) - 1;
                let start = u32::from(ip) & !(mask);
                let end = start + mask;
                Range { start, end }
            }
            ExcludedIps::Range(ip1, ip2) => {
                let ip1 = u32::from(ip1);
                let ip2 = u32::from(ip2);
                let start = cmp::min(ip1, ip2);
                let end = cmp::max(ip1, ip2);
                Range { start, end }
            }
            ExcludedIps::Address(ip) => {
                let start = u32::from(ip);
                let end = start;
                Range { start, end }
            }
        }
    }
}

impl Range {
    /// The ranges of IPs in this range that aren't in the list of exclusion ranges.
    /// Note that the exclusions vector will be modified when running this method.
    pub fn after_excludes(self, mut exclusions: Vec<Range>) -> Vec<Range> {
        if exclusions.is_empty() {
            return vec![self];
        }

        // Trim off exclusion at the edge of of this current range
        let mut current_range = self;
        let mut fully_inside = None;

        // As pointed out by RShields, we can do this multiple times
        let mut indices_to_remove = Vec::with_capacity(exclusions.len());
        let mut done_something = false;
        loop {
            for (i, exclusion) in exclusions.iter().enumerate() {
                if exclusion.start <= current_range.start {
                    current_range.start = cmp::max(current_range.start, exclusion.end + 1);
                    indices_to_remove.push(i);
                    done_something = true;
                } else if exclusion.end >= current_range.end {
                    current_range.end = cmp::min(current_range.end, exclusion.start - 1);
                    indices_to_remove.push(i);
                    done_something = true;
                } else {
                    // The start of the exclusion and end of the exclusion are inside this range
                    fully_inside = Some(*exclusion);
                }
            }

            if !done_something {
                break;
            }
            done_something = false;
            // Reset because fully inside this time doesn't mean the same for next time
            fully_inside = None;
            // Has to be sorted for funky reasons don't question it
            // Elements are added in ascending order (see above loop) so we flip it
            indices_to_remove.reverse();
            for index in indices_to_remove.drain(..) {
                exclusions.remove(index);
            }
        }

        // Split the range by any exclusion fully inside this range, if one exists
        // Then do recursion
        if let Some(exclusion) = fully_inside {
            let split_range_one = Range {
                start: current_range.start,
                end: exclusion.start - 1,
            };
            let split_range_two = Range {
                start: exclusion.end + 1,
                end: current_range.end,
            };

            let mut ret = Vec::new();
            ret.append(&mut split_range_one.after_excludes(exclusions.clone()));
            ret.append(&mut split_range_two.after_excludes(exclusions.clone()));
            ret
        } else {
            // Check for validity
            if current_range.start <= current_range.end {
                vec![current_range]
            } else {
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use proptest_derive::Arbitrary;

    #[test]
    fn masscan_real_ranges() {
        use crate::excludes_parser;
        use std::{fs::File, io::Read};

        let mut excludes_string = String::new();
        let mut file = File::open("exclude.conf.example")
            .expect("exclude.conf.example should be available - have you cloned the repo?");
        file.read_to_string(&mut excludes_string).unwrap();

        let excludes_vec: Vec<Range> = excludes_parser::parse_excludes(&excludes_string)
            .unwrap()
            .into_iter()
            .map(|excluded_ips| excluded_ips.to_range())
            .collect();
        let scan_range = Range {
            start: 0,
            end: u32::MAX,
        };
        let after_excludes = scan_range.after_excludes(excludes_vec.clone());

        test_exclusions(scan_range, after_excludes, excludes_vec);
    }

    #[derive(Arbitrary, Debug, Clone, Copy)]
    struct TestRange {
        start: u32,
        end: u32,
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]
        #[test]
        fn range_exclusion_correct(test_range: TestRange, exclusions: Box<[TestRange]>) {
            use std::cmp;

            let range = Range {
                start: cmp::min(test_range.start, test_range.end),
                end: cmp::max(test_range.start, test_range.end),
            };

            let exclusions: Vec<Range> = exclusions.iter().map(|test_range| {
                Range {
                    start: cmp::min(test_range.start, test_range.end),
                    end: cmp::max(test_range.start, test_range.end),
                }
            }).collect();

            let excluded_ranges = range.after_excludes(exclusions.clone());

            test_exclusions(range, excluded_ranges, exclusions);
        }
    }

    // Test if exclusions are correct
    fn test_exclusions(original_range: Range, with_exclusions: Vec<Range>, exclusions: Vec<Range>) {
        for exclusion in &exclusions {
            for i in [exclusion.start, exclusion.end] {
                // Don't test everything for performance reasons
                if in_ranges(i, &with_exclusions) {
                    panic!("range: {original_range:#?} - exclusions: {exclusions:#?} - i: {i} - excluded_ranges: {with_exclusions:#?}");
                }
            }
        }
    }

    fn in_ranges(i: u32, ranges: &[Range]) -> bool {
        ranges
            .iter()
            .any(|range| i >= range.start && i <= range.end)
    }
}

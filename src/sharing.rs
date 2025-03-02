use std::{collections::BTreeMap, ops::Add};

#[derive(Clone)]
pub struct AuthShare<T, U>
where
    T: for<'a> Add<&'a T>,
    U: for<'a> Add<&'a U>,
{
    // The secret share <x>_i
    pub share: T,
    // The MAC values M_j^i[x], where value M_j^i[x] is under key j
    pub mac_values: BTreeMap<usize, U>,
    // The MAC Keys K_i^j[x], where value K_i^j[x] is under key i
    pub mac_keys: BTreeMap<usize, U>,
}

impl<T, U> Add<&AuthShare<T, U>> for AuthShare<T, U>
where
    T: for<'a> Add<&'a T>,
    U: for<'a> Add<&'a U>,
{
    type Output = AuthShare<T, U>;

    fn add(self, rhs: &AuthShare<T, U>) -> Self::Output {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use scuttlebutt::ring::FiniteRing;
    use swanky_field_binary::{F128b, F2};
    
    #[test]
    fn test_sharing() {
        let share: AuthShare<F2, F128b> = AuthShare {
            share: F2::ZERO,
            mac_keys: BTreeMap::new(),
            mac_values: BTreeMap::new(),
        };
    }
}

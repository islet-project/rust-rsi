use super::*;

pub struct PlatClaims
{
    pub challenge: Vec<u8>,
    pub verification_service: String,
    pub profile: String,
    pub instance_id: Vec<u8>,
    pub implementation_id: Vec<u8>,
    pub lifecycle: i64,
    pub configuration: Vec<u8>,
    pub hash_algo: String,
}

fn get_claim<T: TryFrom<ClaimData>>(key: u32, claims: &ClaimsMap) -> Result<T, TokenError>
{
    let claim = claims.get(&key);

    if let Some(c) = claim {
        if c.present {
            return Ok(c.data.clone().try_into().or(Err(TokenError::ClaimDataMisMatchType))?);
        }
    }

    Err(TokenError::MissingMandatoryClaim(key))
}

impl PlatClaims
{
    pub fn from_raw_claims(claims: &ClaimsMap) -> Result<Self, TokenError>
    {
        Ok(Self {
            challenge: get_claim(CCA_PLAT_CHALLENGE, claims)?,
            verification_service: get_claim(CCA_PLAT_VERIFICATION_SERVICE, claims)?,
            profile: get_claim(CCA_PLAT_PROFILE, claims)?,
            instance_id: get_claim(CCA_PLAT_INSTANCE_ID, claims)?,
            implementation_id: get_claim(CCA_PLAT_IMPLEMENTATION_ID, claims)?,
            lifecycle: get_claim(CCA_PLAT_SECURITY_LIFECYCLE, claims)?,
            configuration: get_claim(CCA_PLAT_CONFIGURATION, claims)?,
            hash_algo: get_claim(CCA_PLAT_HASH_ALGO_ID, claims)?,
        })
    }
}

pub struct PlatSwComponent
{
    pub ty: String,
    pub hash_algo: String,
    pub value: Vec<u8>,
    pub version: String,
    pub signer_id: Vec<u8>,
}

impl PlatSwComponent
{
    pub fn from_raw_claims(claims: &ClaimsMap, plat_hash_algo: &String) -> Result<Self, TokenError>
    {
        Ok(Self {
            ty: get_claim(CCA_SW_COMP_TITLE, claims)?,
            hash_algo: match get_claim(CCA_SW_COMP_HASH_ALGORITHM, claims) {
                Ok(i) => i,
                Err(_) => plat_hash_algo.clone(),
            },
            value: get_claim(CCA_SW_COMP_MEASUREMENT_VALUE, claims)?,
            version: get_claim(CCA_SW_COMP_VERSION, claims)?,
            signer_id: get_claim(CCA_SW_COMP_SIGNER_ID, claims)?,
        })
    }
}

#[derive(Debug)]
pub struct RealmClaims
{
    pub challenge: Vec<u8>,
    pub profile: Option<String>,
    pub personalization_value: Vec<u8>,
    pub hash_algo: String,
    pub pub_key_hash_algo: String,
    pub pub_key: Vec<u8>,
    pub rim: Vec<u8>,
    pub rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS],
}

impl RealmClaims
{
    pub fn from_raw_claims(claims: &ClaimsMap, measurement_claims: &ClaimsMap) -> Result<Self, TokenError>
    {
        let mut rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS] =
            <[Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>::default();
        for i in 0..CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
            rems[i] = get_claim(i as u32, measurement_claims)?;
        }

        Ok(Self {
            challenge: get_claim(CCA_REALM_CHALLENGE, claims)?,
            profile: get_claim(CCA_REALM_PROFILE, claims).ok(), // ignore error, assign None
            personalization_value: get_claim(CCA_REALM_PERSONALIZATION_VALUE, claims)?,
            hash_algo: get_claim(CCA_REALM_HASH_ALGO_ID, claims)?,
            pub_key_hash_algo: get_claim(CCA_REALM_PUB_KEY_HASH_ALGO_ID, claims)?,
            pub_key: get_claim(CCA_REALM_PUB_KEY, claims)?,
            rim: get_claim(CCA_REALM_INITIAL_MEASUREMENT, claims)?,
            rems,
        })
    }
}

pub(super) mod kernel;

use std::os::fd::AsRawFd;

use nix::{errno::Errno, fcntl::OFlag, libc::O_RDWR, sys::stat::Mode};

const FLAGS: OFlag = OFlag::from_bits_truncate(O_RDWR);
const MODE: Mode = Mode::from_bits_truncate(0o644);
const DEV: &str = "/dev/rsi";

pub fn abi_version() -> nix::Result<(u32, u32)>
{
    let fd = nix::fcntl::open("/dev/rsi", FLAGS, MODE)?;
    let mut version = 0;
    kernel::abi_version(fd.as_raw_fd(), &mut version)?;
    Ok((
        kernel::abi_version_get_major(version),
        kernel::abi_version_get_minor(version),
    ))
}

pub fn measurement_read(index: u32) -> nix::Result<Vec<u8>>
{
    let mut measure = [kernel::RsiMeasurement::new_empty(index)];
    let fd = nix::fcntl::open(DEV, FLAGS, MODE)?;
    kernel::measurement_read(fd.as_raw_fd(), &mut measure)?;
    Ok(measure[0].data[..(measure[0].data_len as usize)].to_vec())
}

pub fn measurement_extend(index: u32, data: &[u8]) -> nix::Result<()>
{
    let measur = [kernel::RsiMeasurement::new_from_data(index, data)];
    let fd = nix::fcntl::open(DEV, FLAGS, MODE)?;
    kernel::measurement_extend(fd.as_raw_fd(), &measur)
}

// Use very small value to make sure the ERANGE case is tested.
// Optimally a value of 4096 should be used.
const INITIAL_TOKEN_SIZE: u64 = 64;

pub fn attestation_token(challenge: &[u8; super::CHALLENGE_LEN as usize]) -> nix::Result<Vec<u8>>
{
    let mut attest = [kernel::RsiAttestation::new(challenge, INITIAL_TOKEN_SIZE)];
    let mut token = vec![0 as u8; INITIAL_TOKEN_SIZE as usize];
    attest[0].token = token.as_mut_ptr();

    let fd = nix::fcntl::open(DEV, FLAGS, MODE)?;
    match kernel::attestation_token(fd.as_raw_fd(), &mut attest) {
        Ok(_) => (),
        Err(Errno::ERANGE) => {
            token = vec![0 as u8; attest[0].token_len as usize];
            attest[0].token = token.as_mut_ptr();
            kernel::attestation_token(fd.as_raw_fd(), &mut attest)?;
        }
        Err(e) => return Err(e),
    }
    Ok(token[..(attest[0].token_len as usize)].to_vec())
}

pub fn sealing_key(flags: u64, svn: u64) -> nix::Result<[u8; 32]>
{
    let mut sealing = [kernel::RsiSealingKey::new(flags, svn)];
    let fd = nix::fcntl::open(DEV, FLAGS, MODE)?;
    kernel::sealing_key(fd.as_raw_fd(), &mut sealing)?;
    Ok(sealing[0].realm_sealing_key)
}

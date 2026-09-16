use pqc_slh_dsa::{
    address::{Address, AddressType},
    fors::{self, ForsNodePosition},
    xmss::{self, XmssNodePosition},
    SlhDsaParameterSet,
};

fn exercise_fors(parameter_set: SlhDsaParameterSet) -> Result<(), String> {
    let parameters = parameter_set.parameters();

    let secret_seed = vec![0x11_u8; parameters.n];
    let public_seed = vec![0x22_u8; parameters.n];
    let mut output = vec![0_u8; parameters.n];

    let mut address = Address::new();
    address.set_type_and_clear(AddressType::ForsTree);
    address.set_key_pair_address(0);

    let height =
        u32::try_from(parameters.a).map_err(|_| "FORS height conversion failed".to_owned())?;

    fors::node(
        &parameters,
        &secret_seed,
        &public_seed,
        &address,
        ForsNodePosition {
            key_pair_address: 0,
            height,
            index: 0,
        },
        &mut output,
    )
    .map_err(|error| format!("{} FORS node failed: {error:?}", parameter_set.name()))?;

    println!(
        "FORS {} height={} active-node-bound={}",
        parameter_set.name(),
        parameters.a,
        parameters.a + 1
    );

    Ok(())
}

fn exercise_xmss(parameter_set: SlhDsaParameterSet) -> Result<(), String> {
    let parameters = parameter_set.parameters();

    let secret_seed = vec![0x33_u8; parameters.n];
    let public_seed = vec![0x44_u8; parameters.n];
    let mut output = vec![0_u8; parameters.n];

    let mut address = Address::new();
    address.set_type_and_clear(AddressType::Tree);

    let height =
        u32::try_from(parameters.hp).map_err(|_| "XMSS height conversion failed".to_owned())?;

    xmss::node(
        &parameters,
        &secret_seed,
        &public_seed,
        &address,
        XmssNodePosition { height, index: 0 },
        &mut output,
    )
    .map_err(|error| format!("{} XMSS node failed: {error:?}", parameter_set.name()))?;

    println!(
        "XMSS {} height={} active-node-bound={}",
        parameter_set.name(),
        parameters.hp,
        parameters.hp + 1
    );

    Ok(())
}

fn main() -> Result<(), String> {
    // Structural extrema across the six unique FIPS 205 geometries.
    //
    // FORS:
    //   a=14: 192s / 256s
    //   a=12: 128s
    //   a=9 : 256f
    //
    // XMSS:
    //   hp=9: 128s / 192s
    //   hp=8: 256s
    //   hp=4: 256f
    exercise_fors(SlhDsaParameterSet::Sha2_192s)?;
    exercise_fors(SlhDsaParameterSet::Sha2_128s)?;
    exercise_fors(SlhDsaParameterSet::Sha2_256f)?;

    exercise_xmss(SlhDsaParameterSet::Sha2_128s)?;
    exercise_xmss(SlhDsaParameterSet::Sha2_256s)?;
    exercise_xmss(SlhDsaParameterSet::Sha2_256f)?;

    Ok(())
}

#![cfg(feature = "integration-test")]

#[path = "test_framework/mod.rs"]
#[macro_use]
mod test_framework;

#[cfg(feature = "hotpath")]
#[path = "hotpath_output.rs"]
mod hotpath_output;

use bitcoin::Amount;
use coinswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};
use std::{env, sync::atomic::Ordering::Relaxed, thread};

#[test]
fn hotpath_taker_focus_swap() {
    #[cfg(feature = "hotpath")]
    let hotpath_guard = {
        if env::var_os("HOTPATH_METRICS_SERVER_OFF").is_none() {
            env::set_var("HOTPATH_METRICS_SERVER_OFF", "1");
        }
        hotpath::HotpathGuardBuilder::new("hotpath_taker_focus_swap").build()
    };

    // CI narrows report output by setting HOTPATH_FOCUS=coinswap::taker.
    let makers_config_map = vec![(7102, Some(19061)), (17102, Some(19062))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        test_framework::TestFramework::init(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).expect("taker must exist");

    let _taker_spendable = test_framework::fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    test_framework::fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).expect("maker server should start"))
        })
        .collect::<Vec<_>>();

    test_framework::wait_for_makers_setup(&makers, 120);

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    test_framework::generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_coinswap(swap_params)
        .expect("prepare_coinswap must succeed");

    taker
        .start_coinswap(&summary.swap_id)
        .expect("start_coinswap must succeed");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));

    for t in maker_threads {
        t.join().expect("maker thread must join");
    }

    test_framework.stop();
    block_generation_handle
        .join()
        .expect("block generation thread must join");

    #[cfg(feature = "hotpath")]
    {
        drop(hotpath_guard);
        hotpath_output::print_hotpath_tables_from_env();
    }
}

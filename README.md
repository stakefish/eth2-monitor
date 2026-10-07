# Eth2 Monitor [![Github Actions Status][svg link]][ci link] #

[svg link]: https://github.com/stakefish/eth2-monitor/actions/workflows/main.yml/badge.svg
[ci link]: https://github.com/stakefish/eth2-monitor/actions/workflows/main.yml

Eth2 Monitor serves a few purposes:

* monitors the attestation inclusion distance,
* monitors and alerts slashing events,

## Installation ##

### Binaries ###

You can use pre-built binaries from [the latest published release][releases link].

[releases link]: https://github.com/stakefish/eth2-monitor/releases

### Containers ###

You can use pre-built containers from Github public container registry.

```shell
docker pull ghcr.io/stakefish/eth2-monitor
```

### Sources ###

If you choose to build from sources, use this command:

```shell
make
```

You will find the executable in `bin/eth2-monitor`.

It's recommended to use the latest Go version.

## Install Beacon Node ##

`eth2-monitor` relies on [Beacon Node API](https://ethereum.github.io/beacon-APIs/#/) to query the Beacon
Chain and therefore requires a running Beacon Node (any that implements the Beacon API spec should do, e.g.
Prysm, Lighthouse, etc.).

## Usage ##

Most of the commands (except for slashings) require you to provide public keys of validators you want to monitor.

You can specify the validator public keys in the command line using `-k` option. You can use `-k` multiple times to specify more than one keys. Example:

```shell
eth2-monitor cmd -k a1daf19d432507b70fd83214aba105be66c81307d22b3d242cdecaaca5528c1b1e5e3cac5ef7f9e7456e9d202d0ec887
```

You can use a file if you have a bunch of keys. The format is very simple: one public key per line. Example:

```shell
echo a1daf19d432507b70fd83214aba105be66c81307d22b3d242cdecaaca5528c1b1e5e3cac5ef7f9e7456e9d202d0ec887 > keys.txt
eth2-monitor cmd keys.txt
```

All public keys are hex-encoded and case-insensitive. On the first run, the monitor will convert the keys into indexes: it takes some time if you have many keys. On the second run, the indexes are loaded from a cache.

Here's a more involved example invocation:

```shell
./bin/eth2-monitor monitor --beacon-chain-api <BEACON_NODE_IP_ADDRESS>:<BEACON_API_PORT> --print-successful --log-level trace <VALIDATOR_PUBLIC_KEYS_FILE_PATH>
```

Don't hesitate to run commands with `--help` to learn more about CLI. 😉

### Monitor attestations and proposals ###

You can monitor the attestation inclusion distance for your validators and alert you if it exceeds a certain threshold. The optimal distance [¹](#footnote-1) is being monitored and by default this is set at 2. You can manually set the distance threshold using `-d`. In order to use the absolute distance, add `--use-absolute-distance`.

Example:

```shell
eth2-monitor monitor -d 1 keys.txt
```

You can forward notification to Slack using `--slack-url`.

<span id="footnote-1">¹</span> Optimal distance is the distance between two slots (or blocks) with missed blocks deducted. The optimal distance reflects the best physically possible distance between blocks the attestation is included into the chain. The best optimal distance for an attestation is 0, i.e. the attestation was included at the first possibility. For more information, read [Defining Attestation Effectiveness](https://www.attestant.io/posts/defining-attestation-effectiveness/).

### Monitor Vanila Blocks ###

Optionally, if passed the `eth2-monitor monitor --mev-relays <FILE_PATH>.json [...]` option, eth2-monitor will
inquire given MEV relays after every epoch and, for every tracked proposal in that epoch, check whether a relay
delivered the payload that ended up on chain:

* no relay delivered a payload for the slot and the execution `extra_data` is an EL client default (geth, Nethermind,
  besu, reth, erigon, nimbus, ethrex) or empty: the block was built locally (**vanilla**). `totalVanillaBlocks` is
  incremented, the `lastVanillaBlock*` gauges are set, and a Slack report is sent carrying the block's graffiti,
  `extra_data` and fee recipient, plus the fee recipient the validator registered with the relays
  (`/relay/v1/data/validator_registration`, looked up only for these blocks). The report flags two misconfigurations:
  a validator that is not registered with any configured relay (mev-boost registration broken) and a block fee
  recipient that differs from the registered one (local EL fee recipient wrong). For SSV validators the graffiti names
  the leader operator's node. A vanilla block is reported even when a relay failed that epoch; the report then says
  the sweep was incomplete.
  Client-default `extra_data` is a strong but not absolute signal: relayscan.io shows roughly 0.01 % of
  relay-delivered blocks (4 of ~46 000 in the week to 2026-10-07, all zero-profit self-submissions) with empty or
  stock-client `extra_data`. Those are classified by the relay trace, so one can only reach this report if its relay
  is missing from the list or its data API failed for that slot.
* no relay delivered a payload but `extra_data` carries a builder tag: a builder made the block. If every relay
  answered, `totalRelayAbsentBuilderBlocks` is incremented and a Slack report says the relay is missing from the list
  (or the proposer dealt with the builder directly). If a relay failed, the failed relay most likely delivered it; only
  `totalMissingBidTraces` is incremented.
* a relay delivered a payload whose hash differs from the chain: reported as vanilla.

Before either relay-absent verdict the monitor re-asks every relay for that exact slot
(`proposer_payload_delivered?slot=N`): relay data APIs expose a delivery only 4-10 seconds after slot start and
the epoch sweep runs seconds after the epoch ends, so a trace found on the second look routes the block through
the normal hash comparison instead. Registrations are read from every relay; a block paying any recipient a relay
holds for the key counts as correctly configured, and "not registered" requires every relay to answer 400/404.

Relay absence alone is only an upper bound for local building (a 2025 study found most never-relayed proposers had
dealt with builders once payment and fee-recipient evidence was added), which is why the `extra_data` and
registration cross-checks decide. Alert on `increase(ETH2_totalMissingBidTraces[1h]) > 0` to know when a relay
outage left slots unclassified.

**The relay list should contain every relay your validators' mev-boost is configured with.** A block delivered by a
relay that is not in the file is reported as a relay-absent builder block rather than vanilla. Copy the list from the
mev-boost configuration.

Format of the JSON file is as follows (public mainnet relays; verify each public key against the relay's homepage and
keep the list identical to the relays your validators' mev-boost is configured with, including any duplicate hostnames
per relay key):
```json
[
    "https://0x8c4ed5e24fe5c6ae21018437bde147693f68cda427cd1122cf20819c30eda7ed74f72dece09bb313f2a1855595ab677d@regional.titanrelay.xyz",
    "https://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@boost-relay.flashbots.net",
    "https://0xa1559ace749633b997cb3fdacffb890aeebdb0f5a3b6aaa7eeeaf1a38af0a8fe88b9e4b1f61f236d2e64d95733327a62@relay-filtered.ultrasound.money",
    "https://0xa7ab7a996c8584251c8f925da3170bdfd6ebc75d50f5ddc4050a6fdc77f2a3b5fce2cc750d0865e05d7228af97d69561@agnostic-relay.net",
    "https://0xa15b52576bcbf1072f4a011c0f99f9fb6c66f3e1ff321f11f461d15e31b1cb359caa092c71bbded0bae5b5ea401aab7e@aestus.live",
    "https://0x8c4ed5e24fe5c6ae21018437bde147693f68cda427cd1122cf20819c30eda7ed74f72dece09bb313f2a1855595ab677d@global.titanrelay.xyz",
    "https://0xa1559ace749633b997cb3fdacffb890aeebdb0f5a3b6aaa7eeeaf1a38af0a8fe88b9e4b1f61f236d2e64d95733327a62@relay.ultrasound.money",
    "https://0xb0b07cd0abef743db4260b0ed50619cf6ad4d82064cb4fbec9d3ec530f7c5e6793d9f286c4e082c0244ffb9f2658fe88@bloxroute.regulated.blxrbdn.com"
]
```

### Monitor slashings ###

You can monitor slashing and send notifications to Slack or Twitter. Use `--slack-url` for Slack, and `--twitter-*` CLI options for Twitter. See `--help` for more details.

To use the reward, use `--show-reward`. Please, note, it's highly inaccurate, slow and experimental.

Example:

```shell
eth2-monitor slashings --slack-url https://hooks.slack.com/services/YOUR_TOKEN
```

At stakefish, we use it for [our Twitter bot](https://twitter.com/Eth2SlashBot).

## Test environment

Set up a test environment by docker-comppose.

```shell
cd test-env
cp env.example .env
cp mev-relays.json.example mev-relays.json
cp validators.txt.example validators.txt
```

Please modify `.env`, `mev-relays.json` and `validators.txt` if needed

```shell
docker-compose up
```

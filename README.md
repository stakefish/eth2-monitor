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

```
docker pull ghcr.io/stakefish/eth2-monitor
```

### Sources ###

If you choose to build from sources, use this command:

``` shell
make
```

You will find the executable in `bin/eth2-monitor`.

It's recommended to use the latest Go version.

## Install Prysm beacon node ##

`eth2-monitor` relies on [Beacon Node API](https://ethereum.github.io/beacon-APIs/#/) to query the Beacon
Chain.  You can re-use your existing Prysm beacon node or set up another one.

## Usage ##

Most of the commands (except for slashings) require you to provide public keys of validators you want to monitor.

You can specify the validator public keys in the command line using `-k` option. You can use `-k` multiple times to specify more than one keys. Example:

``` shell
eth2-monitor cmd -k a1daf19d432507b70fd83214aba105be66c81307d22b3d242cdecaaca5528c1b1e5e3cac5ef7f9e7456e9d202d0ec887
```

You can use a file if you have a bunch of keys. The format is very simple: one public key per line. Example:

``` shell
echo a1daf19d432507b70fd83214aba105be66c81307d22b3d242cdecaaca5528c1b1e5e3cac5ef7f9e7456e9d202d0ec887 > keys.txt
eth2-monitor cmd keys.txt
```

All public keys are hex-encoded and case-insensitive. On the first run, the monitor will convert the keys into indexes: it takes some time if you have many keys. On the second run, the indexes are loaded from a cache.

Here's a more involved example invocation:

```
./bin/eth2-monitor monitor --beacon-chain-api <PRYSM_NODE_IP_ADDRESS>:3500 --print-successful --log-level trace <VALIDATOR_PUBLIC_KEYS_FILE_PATH>
```

Don't hesitate to run commands with `--help` to learn more about CLI. 😉

### Monitor attestations ###

You can monitor the attestation inclusion distance for your validators and alert you if it exceeds a certain threshold. The optimal distance [¹](#footnote-1) is being monitored and by default this is set at 2. You can manually set the distance threshold using `-d`. In order to use the absolute distance, add `--use-absolute-distance`.

Example:

``` shell
eth2-monitor monitor -d 1 keys.txt
```

You can forward notification to Slack using `--slack-url`.

<span id="footnote-1">¹</span> Optimal distance is the distance between two slots (or blocks) with missed blocks deducted. The optimal distance reflects the best physically possible distance between blocks the attestation is included into the chain. The best optimal distance for an attestation is 0, i.e. the attestation was included at the first possibility. For more information, read [Defining Attestation Effectiveness](https://www.attestant.io/posts/defining-attestation-effectiveness/).

### Monitor slashings ###

You can monitor slashing and send notifications to Slack or Twitter. Use `--slack-url` for Slack, and `--twitter-*` CLI options for Twitter. See `--help` for more details.

To use the reward, use `--show-reward`. Please, note, it's highly inaccurate, slow and experimental.

Example:

``` shell
eth2-monitor slashings --slack-url https://hooks.slack.com/services/YOUR_TOKEN
```

At stakefish, we use it for [our Twitter bot](https://twitter.com/Eth2SlashBot).

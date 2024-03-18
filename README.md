# Eth2 Monitor [![Github Actions Status][svg link]][ci link] #

[svg link]: https://github.com/stakefish/eth2-monitor/actions/workflows/main.yml/badge.svg
[ci link]: https://github.com/stakefish/eth2-monitor/actions/workflows/main.yml

Eth2 Monitor serves a few purposes:

* monitors the attestation inclusion distance,
* monitors and alerts slashing events,
* exports rewards history and other data (TBD).

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

`eth2-monitor` uses Prysm's GRPC API in order to query the Beacon Chain.
You can re-use your existing Prysm beacon node or set up another one.

Here is an example of how you can sync a Prysm beacon node:

``` shell
docker run                                                                              \
  -v "${HOME}/prysm":/data                                                              \
  -p 0.0.0.0:4000:4000/tcp                                                              \
  -p 0.0.0.0:13000:13000                                                                \
  -p 0.0.0.0:12000:12000/udp                                                            \
  --rm                                                                                  \
  --name prysm                                                                          \
  gcr.io/prysmaticlabs/prysm/beacon-chain:stable                                        \
    --accept-terms-of-use                                                               \
    --mainnet                                                                           \
    --datadir /data                                                                     \
    --http-web3provider https://mainnet.infura.io/v3/YOUR_TOKEN                         \
    --rpc-host 0.0.0.0
```

If you want to export a large amount of data involving all validators, add `--grpc-max-msg-size 419430400 --rpc-max-page-size 100000` to achieve adequate performance.

Note, GRPC uses port 4000/tcp by default.

Use `--beacon-node` to work with a remote Prysm. By default, the monitor connects to `localhost:4000`.

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

### Export rewards history and other data (TBD) ###

In case you want to see your rewards history, you can export it as a CSV file or into a PostgreSQL database.

``` shell
eth2-monitor export -o my-validators-rewards keys.txt
```

If no keys are specified, all validators will be exported.

The format of the exported data is subject to modifications, and the schema may change in future releases.

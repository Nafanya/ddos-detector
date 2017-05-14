# DDoS Guard

[SYN flood](https://en.wikipedia.org/wiki/SYN_flood) and connection flood DDoS detector and preventor.
Works as simple python wrapper over `netstat` and `iptables` commands. Requires root access (to add rules to iptables).

## Usage

```bash
$ python3 guard.py OPTIONS
```

or

```bash
$ ./guard.py OPTIONS
```

## Options

List of available options

| Option         | Required | Default     | Description                                                                       |
| :------------- | :------- | :---------- | :----------                                                                       |
| `--soft-limit` | `no`     | `10`        | Minimal number of connections on address:port to show in logs as potential attack |
| `--hard-limit` | `no`     | `100`       | Number of connections to be treated as a real attack                              |
| `--demo`       | `no`     | `False`     | Demo mode, iptables rules are not added                                           |


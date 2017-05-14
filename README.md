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

## In action

Main view lists two types of attacks: `SYN flood` and `connection flood`.

<img src="https://github.com/Nafanya/ddos-detector/blob/master/media/main.png">

Connection flood attack on an `nginx` server listening on port `8080` on `localhost` is is simulated with `apache benchmark` (`ab`) tool as following:

```bash
$ ab -n 100000 -c 200 http://127.0.0.1:8080/
```

Since `--hard-limit` option is set to default value of `100`, the attack is treated as real and corresponding rule is added to `iptables`:

```bash
$ sudo iptables -A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 8080 -j DROP
```

<img src="https://github.com/Nafanya/ddos-detector/blob/master/media/in-action.png">

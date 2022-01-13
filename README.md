# tcpip38

## How to build

```sh
cargo build --examples
```

## How to run

Setup Vertual Network on your Linux.
```sh
./setup.sh
```

Run nc as tcpip server.
```sh
sudo ip netns exec host2 nc -l 10.0.1.1 40000
```

Run tcpdump to capture packets.
```sh
sudo ip netns exec host1 tcpdump -l
```


```
sudo ip netns exec host2 ./target/debug/examples/echoserver 10.0.1.1 40000
```

```sh
sudo ip netns exec host1 ./target/debug/examples/echoclient 10.0.1.1 40000
```

Configure packet loss condition.
```
sudo ip netns exec host1 tc qdisc add dev host1-veth1 root netem loss 50%
```

Cancel packet loss condition.
```
sudo ip netns exec host1 tc qdisc del dev host1-veth1 root
```
## References

- Rustで始めるTCP自作入門
- 竹下隆史, 村山公保, 荒井透, 苅田幸雄: マスタリングTCP/IP 入門編 第5版, オーム社 (2012)

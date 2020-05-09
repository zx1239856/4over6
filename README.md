# 4over6 Linux Server/Client

(Tested on ` Ubuntu 18.04/20.04/CentOS 8`)

## Build and Install

The build system is `CMake`. You need to install the following dependencies first (on Ubuntu for example, and you should find the equivalent packages rather easily on CentOS or other Linux distributions, such as `libsodium-devel`)

```bash
sudo apt-get install libboost-all-dev libyaml-cpp-dev pkgconf libsodium-dev
```

By default, if you have `libsodium` installed, encryption will be available. If you want to disable it, please build with the following parameters

```bash
cmake .. -DNoEncrypt=ON
```

## How to Run

#### Server

First startup server

```bash
sudo ./server --conf <path-to-config>
```

The example config file is  here [server_config.yaml](./server_config.yaml).

The server will setup a TUN device automatically and assign an IP address to it, as specified in your config.

Afterwards, execute the following script to enable IPv4 forwarding in your system

```bash
sudo ./nat.sh
```

If you want to know the complete commands available, use `--help` flag.

#### Client

Much similar to server

```bash
sudo ./client --conf <path-to-config>
```

You can use a domain name (with valid `AAAA` record) in the `server` section of config file. If you provide `pk` in config, the encryption will be enabled, so clear this line if you do not want to enable this feature.
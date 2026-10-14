# gpg-agent-forward

让远端 Linux 主机借用 Windows 上 `gpg-agent` 里的 OpenPGP 私钥签名，例如插在 Windows 上的
YubiKey。私钥不离开 Windows，也不用 ssh 签名。

## 为什么需要一个中继

Windows 没有 `AF_UNIX`。libassuan 用回环 TCP 加一段 16 字节 nonce 来模拟 agent 的 socket：

- socket 文件（默认 `%LOCALAPPDATA%\gnupg\S.gpg-agent.extra`）里是 ASCII 十进制端口号、一个换行，
  然后是 16 字节原始 nonce
- 客户端必须连上那个回环端口，并把 nonce 作为首字节发出去，否则 agent 直接断开

`ssh -R` 只能转发 TCP，做不了这个握手。所以 Windows 侧需要一个中继进程：

```
远端 Linux 主机                          Windows 主机
gpg                                      ssh.exe
 |  连接 agent-socket 路径               |  拨 127.0.0.1:29173
 v                                       v
sshd  ========= ssh 隧道 (-R) ========>  relay (gpg-agent-forward serve)
                                           |  读 socket 文件, 拨号, 重放 nonce
                                           v
                                         gpg-agent  ->  YubiKey
```

- sshd 把 `-R` 的路径发布成远端的一个 unix socket（OpenSSH 的 stream-local 转发），远端 `gpg`
  连的就是它
- 中继每个连接都重读 socket 文件，所以 agent 重启（换了端口与 nonce）之后隧道依然可用
- 只转发 agent 的 extra socket。GnuPG 为这种远端转发场景专门提供它：允许签名与解密，拒绝导入、
  导出、删除与生成密钥，也拒绝预置口令
- 口令提示与刷卡确认仍然出现在 Windows 桌面上，PIN 不过 SSH 链路

## 要求

Windows（运行 `gpg-agent-forward` 的一侧）：

- Windows 10 及以上，带 OpenSSH 客户端（`ssh.exe`）
- GnuPG 已安装，`gpg-agent` 在运行，extra socket 文件存在（`doctor` 可以检查）
- `gpg-agent-forward` 与 `ssh.exe` 必须是同一个用户：中继在 Windows 上只接受本用户 ssh 客户端的连接

远端：

- Linux，`gpg` 与 `gpgconf` 在 `PATH` 里
- sshd 支持 stream-local 转发（OpenSSH 6.7 及以上），且没有用 `AllowStreamLocalForwarding` 或
  `PermitOpen` 把它禁掉
- 目标路径上不能已经有别的 agent 在监听。远端自己跑着 `gpg-agent` 时先停掉它：

```
gpgconf --kill gpg-agent
echo no-autostart >> ~/.gnupg/gpg.conf
```

## 构建

需要 Go 1.26 及以上（见 `go.mod`），唯一的第三方依赖是 `golang.org/x/sys`。

```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
  -o dist/gpg-agent-forward-windows-amd64.exe ./cmd/gpg-agent-forward
```

测试在任何平台都能跑：`go test ./...`（要用到 `ssh`、`unshare` 之类条件的用例，缺条件时跳过）。

## 用法

### `ssh`

在 Windows 上开一个带转发的会话：

```
gpg-agent-forward ssh dev@build-box.example
```

它先问远端它的 agent socket 路径在哪，再检查那个路径，再确保中继在运行，然后按

```
ssh -R <远端 socket 路径>:127.0.0.1:<port> ...
```

运行 ssh。会话里远端 `gpg` 的签名请求就落在这个 socket 上：

```
dev@build-box:~$ git commit -S -m "..."
```

本工具自己的选项从 ssh 参数里挑出来，其余参数原样透传并保持顺序；和 ssh 一样，选项可以跟在主机后面，
`--` 之后的全是 ssh 的：

```
gpg-agent-forward ssh -p 2222 dev@build-box.example
gpg-agent-forward ssh --remote-socket /run/user/1000/gnupg/S.gpg-agent.extra dev@build-box.example
gpg-agent-forward ssh --skip-remote-check dev@build-box.example
gpg-agent-forward ssh -- -o ProxyJump=bastion dev@build-box.example
```

### `serve`

前台运行中继。启动时就会解析 socket 文件，文件不对立刻报错，而不是拖到每次连接都失败。

```
gpg-agent-forward serve --socket-file "%LOCALAPPDATA%\gnupg\S.gpg-agent.extra" --port 29173 --idle 15m
```

`--idle` 到期且没有连接在飞就退出，退出码 0。`ssh` 会话用的中继不走这条路：它禁用闲置退出，生命
周期跟着会话。

### `ensure`

中继没在跑就起一个（用给定的 `--idle`），然后返回；已经在跑，而且转发的是同一个 socket 文件，就
什么都不做。

### `doctor`

自检，不需要 gpg，也不需要远端主机：

```
gpg-agent-forward doctor
```

报告 socket 文件能否解析、agent 握手能否完成、Windows 上的对端策略是否真的在生效、以及端口是不是
空着。非 Windows 上没有对端策略可谈，这一项报 `n/a`。

### 选项

| 选项 | 适用的子命令 | 说明 |
| --- | --- | --- |
| `--socket-file PATH` | `serve` `ensure` `ssh` `doctor` | Windows gpg-agent socket 文件，默认 `%LOCALAPPDATA%\gnupg\S.gpg-agent.extra` |
| `--port N` | 全部 | 中继监听的端口，默认 `29173` |
| `--idle DURATION` | `serve` `ensure` | 无连接这么久后退出，默认 `15m`，`0` 表示不退出；`ssh` 接受该选项但忽略它 |
| `--remote-socket PATH` | `ssh` | 在远端创建的 socket 路径，默认问远端的 `gpgconf --list-dirs agent-socket` |
| `--skip-remote-check` | `ssh` | 预检根本没做成时仍然起会话 |

远端路径不猜：它取决于远端 uid 和自定义 homedir，猜错会让 gpg 用远端密钥签名却像是成功，所以默认
直接问远端的 `gpgconf`。

## 远端预检

远端路径上如果留着上一次会话的 socket 文件，它挡着 bind，下一个会话就起不来。所以会话开始前要弄清
楚那个路径的现状。

判断依据是远端主机自己的连接，而不是读它的 socket 表：socket 表只描述一个网络命名空间，别的命名
空间里的监听者（例如共享目录上的容器 agent）在读表时两边都不出现，会被当成残留删掉。

检查分三步，只有第三步可能删除：

1. 问路径上是什么，只用 shell 内建命令。不存在就是健康；不可写、不是 socket 都拒绝，什么都不动
2. 阳性对照：让远端主机连一个紧挨着被测路径创建的 socket，证明这条连接上 stream-local 连接本来
   就是允许的（这个 socket 是检查自己的，用完即删）
3. 让远端主机连被测路径：连接沉默地保持住就是有监听者，会话停下；连上以后没答话就结束，而且对照
   在手，才是残留，删除它

预检做不成（问不到主机，或主机答不了）一律拒绝，不猜。`--skip-remote-check` 只覆盖这种情况，也就
是检查根本没有结论的时候；路径自身给出的结论（有监听者、不是 socket、删不掉的残留）不会被这个开关
推翻。不可写也不能跳过：能连一下看有没有人应答，前提正是对这个路径有写权限，没有它，被拒的连接和
没人监听就是同一个现象，这时该做的是换一个路径（`--remote-socket`），而不是硬来。

路径的字节以八进制转义下发到远端，不上命令行：远端登录 shell 可能是 csh 或 tcsh，它连单引号里也做
历史展开，路径里的 `!`、`$`、反引号或 `~` 会让命令什么都不跑。

## 安全模型

- **只监听回环**：中继拒绝非回环的监听地址，也拒绝主机名，因为解析结果会被 `hosts` 之类的文件左右
- **对端校验（仅 Windows）**：回环端口本身不说明谁在连，所以每个连接都要求对端是同一个用户的
  `ssh.exe`。对端 pid 取自系统 TCP 表，不是客户端自报的值，再按进程映像路径与 token 里的 SID 判定。
  这是补偿控制，真正的信任边界仍是 agent 的 nonce 文件
- **身份锁**：中继在每用户私有目录里持一把排他锁，并用旁边的元数据文件记下自己转发的是哪个 socket
  文件。调用方靠这把锁证明端口上坐着的是本工具的中继，而不是恰好占着端口的外来进程。拿不到锁一律
  按没有中继处理，绝不放行
- **extra socket 的边界**：导入、导出、删除、生成密钥与预置口令都被 agent 拒绝
- **PIN 不过链路**：口令提示与刷卡确认都留在 Windows 桌面

## 排查

先跑 `gpg-agent-forward doctor`。另外两个常见的拦路虎：

- 端口上已经有一个为别的 socket 文件服务的中继：报错会写明是哪个文件，先结束那个进程再起
- 远端路径被远端自己的 agent 占着：报错里带着停 agent 的两条命令

## 许可证

MIT，见 [LICENSE](LICENSE)。

发布的二进制里静态链接了 `golang.org/x/sys`（BSD-3-Clause，Copyright 2009 The Go Authors），它是
本项目唯一的第三方依赖。BSD-3-Clause 要求再分发二进制时给出它的版权声明与许可条款，随二进制一起
发布的 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) 就是这段文本。

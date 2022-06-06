## 环境配置




## 清理数据
```shell
## 取消xdp模式
ip link set dev ns-link-2 xdp off

clean=(map prog)
for i in ${clean[@]}; do ls -h /sys/fs/bpf/$i/ | xargs -I {} sudo unlink /sys/fs/bpf/$i/{}; done

```

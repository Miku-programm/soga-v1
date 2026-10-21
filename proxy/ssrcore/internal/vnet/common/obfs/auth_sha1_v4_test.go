package obfs

import (
	"bytes"
	"testing"

	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/core"
)

func newV4Pair(t *testing.T) (Plain, Plain) {
	t.Helper()
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("auth_sha1_v4"))
	newSide := func() Plain {
		p, err := GetObfs("auth_sha1_v4")
		if err != nil {
			t.Fatal(err)
		}
		s := NewServerInfo()
		s.SetPort(8080)
		s.SetProtocolParam("64")
		s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetKey(MustHexDecode("b36d331451a61eb2d76860e00c347396"))
		s.SetHeadLen(30)
		p.SetServerInfo(s)
		return p
	}
	return newSide(), newSide()
}

// 双向回环 + 三种补长分支（>1200 单标记、400~1200 短标记、<=400 可能走 255 长标记）都要过一遍
func TestAuthSha1V4RoundTrip(t *testing.T) {
	for _, size := range []int{5, 401, 1201, 1500, 9000} {
		client, server := newV4Pair(t)
		payload := bytes.Repeat([]byte("q"), size)
		encoded, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%d 字节客户端封装失败: %v", size, err)
		}
		decoded, _, err := server.ServerPostDecrypt(encoded)
		if err != nil {
			t.Fatalf("%d 字节服务端解包失败: %v", size, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("%d 字节 c→s 回环不符，解出 %d 字节", size, len(decoded))
		}

		back := bytes.Repeat([]byte("a"), size)
		sealed, err := server.ServerPreEncrypt(back)
		if err != nil {
			t.Fatalf("%d 字节服务端封装失败: %v", size, err)
		}
		got, err := client.ClientPostDecrypt(sealed)
		if err != nil {
			t.Fatalf("%d 字节客户端解包失败: %v", size, err)
		}
		if !bytes.Equal(got, back) {
			t.Fatalf("%d 字节 s→c 回环不符", size)
		}
	}
}

// 篡改首帧正文必须被帧尾 HMAC-SHA1 拦住。补长段长度随机，
// 多跑几轮以覆盖单字节标记和 255 长标记两种情况
func TestAuthSha1V4RejectsTamperedFrame(t *testing.T) {
	for i := 0; i < 64; i++ {
		client, server := newV4Pair(t)
		payload := bytes.Repeat([]byte("k"), 60)
		encoded, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatal(err)
		}
		// 首帧是认证帧：长度2 + crc32 4 + 补长段 + 12 字节 auth 前缀
		// （utc+client+connection）+ 至少 30 字节正文 + HMAC 10
		body := 6 + skipLen(encoded[6], encoded[6:9]) + 12
		frameLen := int(encoded[0])<<8 | int(encoded[1])
		if body >= frameLen-10 {
			t.Fatalf("正文起点 %d 落在校验区内（帧长 %d）", body, frameLen)
		}
		encoded[body] ^= 0xFF

		out, _, err := server.ServerPostDecrypt(encoded)
		if err == nil && bytes.Contains(out, payload) {
			t.Fatal("篡改帧被静默接受了")
		}
	}
}

// 同一 (client_id, connection_id) 重放必须被拒：解出原文才算没拒
func TestAuthSha1V4RejectsReplay(t *testing.T) {
	client, server := newV4Pair(t)
	encoded, err := client.ClientPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ServerPostDecrypt(encoded); err != nil {
		t.Fatal(err)
	}
	replay, _, err := server.ServerPostDecrypt(append([]byte{}, encoded...))
	if err != nil {
		return // 校验失败即拒绝，合格
	}
	if bytes.Contains(replay, []byte("hello")) {
		t.Fatalf("重放解出了原文: %q", replay)
	}
}

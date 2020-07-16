package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/pflag"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var host_url = pflag.StringP("url", "l", "https://www.shadowsky.icu", "host url")
var username = pflag.StringP("username", "u", "", "host username")
var password = pflag.StringP("password", "p", "", "host password")
var timeSecond = pflag.IntP("time_second", "s", 3600, "时间")

type UserArr struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}
type ConfigJson struct {
	UserPass []*UserArr `json:"userPass"`
}

var JsonConfig *ConfigJson

func (c *ConfigJson) initConfigJson() (err error) {
	var (
		content  []byte
		filename string
	)

	if filename == "" {

		filename = "./config.json"
	} else {
		filename = strings.TrimRight(filename, "yaml") + "json"
	}
	// 1, 把配置文件读进来
	if content, err = ioutil.ReadFile(filename); err != nil {

		return
	}
	c = &ConfigJson{
		UserPass: make([]*UserArr, 0),
	}

	// 2, 做JSON反序列化
	if err = json.Unmarshal(content, &c); err != nil {
		return
	}

	// 3, 赋值单例
	JsonConfig = c

	return
}

func main() {

	pflag.Parse()
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("错误", r)

		}
	}()
	var c = make(chan bool)

	//orig := "wbw19950202" // m7bS7fijj73tzm07UYc3Gg==   || xz     rZeUyPguBOM0EpqdPB065g==
	//key := "0123456789012345"

	//fmt.Println("原文：", orig)
	//encryptCode := AesEncrypt(orig, key)
	//fmt.Println("密文：" , encryptCode)
	//decryptCode := AesDecrypt(encryptCode, key)
	//fmt.Println("解密结果：", decryptCode)

	// go build -o go_ulive_app -ldflags "-X main.VERSION=1.0.4 -X 'main.BUILD_TIME=`date`' -s -w" -gcflags "-N -l" ./main.go

	// https://www.shadowsky.icu
	//https://www.shadowsky.icu/auth/login
	// https://www.shadowsky.icu/user/checkin

	urlSignUp := *host_url + "/auth/login"
	urlCheckin := *host_url + "/user/checkin"
	userName := strings.TrimSpace(*username)
	passWord := strings.TrimSpace(*password)
	if userName == "" || passWord == "" {
		time.Sleep(5 * time.Second)
		model := &ConfigJson{}
		if err := model.initConfigJson(); err != nil {
			fmt.Println(err)
			return
		}
		//time.Seed

		rand.Seed(time.Now().UnixNano()) // initialize global pseudo random generator

		for _, value := range JsonConfig.UserPass {
			//fmt.Println(urlSignUp,urlCheckin,value.UserName,value.Password);
			go send(urlSignUp, urlCheckin, value.UserName, value.Password)
		}

	} else {
		go send(urlSignUp, urlCheckin, userName, passWord)

	}

	<-c

}

func send(urlSignUp, urlCheckin, userName, passWord string) {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("错误2", r)

		}
	}()
	fmt.Println(userName)
	pushRes := map[string]string{
		//"email":      `gitxuzan@126.com`,
		"email":       userName,
		"passwd":      passWord,
		"remember_me": `week`,
	}

	headerResAll := map[string]string{
		"User-Agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36`,
	}
	for {

		resAll, resp, err := PostFormData(urlSignUp, pushRes, headerResAll)
		if err != nil {
			fmt.Println(err)
		} else {

			cookies := resAll.Header.Get("Set-Cookie")
			if cookies != "" {
				//fmt.Println(gjson.Get(string(resp),"msg"));

				fmt.Println(resAll.Header.Get("Set-Cookie"), string(resp))

				headerRes := map[string]string{
					"Cookie":     cookies,
					"User-Agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36`,
				}
				_, resp, err := PostFormData(urlCheckin, map[string]string{}, headerRes)
				if err != nil {
					fmt.Println(err)

				} else {
					//fmt.Println(string(resp));
					var cstZone = time.FixedZone("CST", 8*3600) // 东八
					timeCur := time.Now().In(cstZone).Format("2006-01-02 15:04:05")
					fmt.Println(timeCur, userName, gjson.Get(string(resp), "msg"))
				}
			}
		}
		timeS := rand.Intn(200) + *timeSecond
		//timeS :=  *timeSecond
		fmt.Println("time:", timeS)
		time.Sleep(time.Second * time.Duration(timeS))
	}
}

func PostFormData(url string, mapStr map[string]string, headerArr ...map[string]string) (*http.Response, []byte, error) {

	//url = "https://sms-api.upyun.com/api/messages"
	method := "POST"
	str := ""
	if len(mapStr) > 0 {
		strArr := []string{}
		for key, value := range mapStr {
			strArr = append(strArr, key+"="+value)
		}
		str = strings.Join(strArr, "&")
	}
	//payload := strings.NewReader("mobile=13291816017&template_id=2661&vars=4453|6")
	payload := strings.NewReader(str)

	// -------------------------  设置超时  -----------------------

	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
	}
	if len(headerArr) > 0 {
		for key, value := range headerArr[0] {
			//req.Header.Add("Authorization", "3eex8dY04BdU1amui6bf20ECgtyc9s")
			req.Header.Add(key, value)
		}
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	return res, body, err

	//fmt.Println(string(body))
}

//func main() {
//	orig := "wbw19950202"
//	key := "0123456789012345"
//
//	fmt.Println("原文：", orig)
//	encryptCode := AesEncrypt(orig, key)
//	fmt.Println("密文：" , encryptCode)
//	decryptCode := AesDecrypt(encryptCode, key)
//	fmt.Println("解密结果：", decryptCode)
//}
func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted)
}
func AesDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

//补码
//AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

package set1

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/mipearson/matasano"
)

func checkForExpectedCandidate(c Candidates, expected Candidate, debug bool) bool {
	found := false
	for _, candidate := range c {
		if debug {
			fmt.Printf("key: %q score: %d plaintext: %q\n", candidate.key, candidate.Score(), candidate.plaintext)
		}
		if bytes.Equal(candidate.plaintext, expected.plaintext) && bytes.Equal(candidate.key, expected.key) {
			found = true
		}
	}
	return found
}

func TestDecodeSimpleXorCipher(t *testing.T) {
	ciphertext := matasano.Hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := Candidate{
		plaintext: []byte("Cooking MC's like a pound of bacon"),
		key:       []byte{'X'},
	}

	candidates := DecodeSimpleXorCipher(ciphertext.Decode()).Top(5)
	if !checkForExpectedCandidate(candidates, expected, false) {
		t.Errorf("TestDecodeSimpleXorCipher could not find matching plaintext from %s", ciphertext)
	}
}

func TestFindSimpleXorCipheredString(t *testing.T) {
	file, err := ioutil.ReadFile("../data/set1_challenge4.txt")
	matasano.CheckErr(err)
	ciphertexts := bytes.Split(file, []byte{'\n'})

	candidates := Candidates{}
	for _, text := range ciphertexts {
		cipher := matasano.Hex(bytes.TrimSpace(text))
		candidates = append(candidates, DecodeSimpleXorCipher(cipher.Decode())...)
	}
	expected := Candidate{
		plaintext: []byte("Now that the party is jumping\n"),
		key:       []byte{'5'},
	}
	if !checkForExpectedCandidate(candidates.Top(5), expected, false) {
		t.Errorf("TestFindSimpleXorCipheredString could not find matching plaintext")
	}
}

var repeatingKeyCases = []struct {
	plaintext []byte
	key       []byte
	cipher    matasano.Base64
}{
	{
		[]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
		[]byte("ICE"),
		matasano.Base64("CzY3JyorLmNiLC5paSojaToqPGMkIC1iPWM0PComImMkJydlJyooKy8gQwplLixlKjEkMzplPisgJ2MMaSsgKDFlKGMmMC4nKC8="),
	},
	{
		[]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
		[]byte("Z22qbcPASAQ&255"),
		matasano.Base64("GEdAHwsNN2F0JDwKElxTektdBEICOS90NXFXR1xWMRJTHwZDPig+Iz1DOHwVPV0SEhACKjhzNjlDXBV8elpXEBBDMWEwODxEU1k="),
	},
	{
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
		[]byte("S3_fFjS$sAT*qC"),
		matasano.Base64("H1wtAytKOlQANDkKFSw/XC1GNQMnBBIsMV5dYzBcMRUjCSdBBzQmChAnOkM2FSUDPUNTJDhDBW9zQDoCZg48BBYoIVkcLDcTKwMrGjxWUyg6SRgnOlcqCDJKJlBTLTVIHjE2EzoSZg48SBwzMQocIjRdPkYnBjpVBiB6CiQ3c1YxDytKMkBTLD1EGC5zRToILws+CFMwIUMCYz1cLBI0HzcEFjkxWBIqJ1IrDykEc1EfLTVHEixzXz4EKRg6V1MvPVkYYyZHfwcqAyJRGjF0TwljNlJ/BSkHPksXLnRJHi0gVi4TJx59BDc0PVlRIiZHOkYvGCZWFmEwRR0sIRM2CGYYNlQBJDxPHyc2QTYSZgM9BAUuOF8BNzJHOkYwDz9NB2ExWQImc1A2CiofPgQXLjhFAyZzVipGIB80TRI1dEQELz9SfxYnGDpFBzQmBFEGK1A6FjIPJlZTMj1EBWM8UDwHIwkyUFMiIVoYJzJHPhJmBDxKUzEmRRgnNl0rSmYZJkoHYT1EUSAmXy8HZhsmTVMuMkwYIDpSfwIjGTZWBi8gChwsP182EmYLPU0eYT1OUSYgR38KJwg8VgYseg=="),
	},
}

func TestRepeatingKeyXor(t *testing.T) {
	for _, test := range repeatingKeyCases {
		got := matasano.ToBase64(RepeatingKeyXOR(test.plaintext, test.key))
		if !bytes.Equal(got, test.cipher) {
			t.Errorf("TestRepeatingKeyXor(%q, %q) got %q, expected %q", test.plaintext, test.key, got, test.cipher)
		}
	}

}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")
	expected := 37

	got := HammingDistance(a, b)
	if got != expected {
		t.Errorf("TextHammingDistance(%q, %q): got %d, expected %d", a, b, got, expected)
	}
}

func TestGuessKeysize(t *testing.T) {
	for _, test := range repeatingKeyCases {
		got := GuessKeysize(test.cipher.Decode()).Top(2)
		expected := len(test.key)

		if !got.ContainsSize(expected) {
			t.Errorf("TestGuessKeySize(%q): got %+v, expected one to have size %d", test.cipher, got, expected)
		}
	}
}

func TestGuessRepeatingKey(t *testing.T) {
	text, err := ioutil.ReadFile("../data/set1_challenge6.txt")
	matasano.CheckErr(err)

	cipher := matasano.Base64(text).Decode()
	candidates := GuessRepeatingKey(cipher)
	expected := Candidate{
		key:       []byte("Terminator X: Bring the noise"),
		plaintext: []byte("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"),
	}

	if !checkForExpectedCandidate(candidates, expected, false) {
		t.Errorf("TestGuessRepeatingKey could not find matching plaintext")
	}
}

func TestDecryptAndEncryptAESECB(t *testing.T) {
	text, err := ioutil.ReadFile("../data/set1_challenge7.txt")
	matasano.CheckErr(err)
	cipher := matasano.Base64(text).Decode()
	key := []byte("YELLOW SUBMARINE")
	expected := []byte("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04")

	got := matasano.DecryptAESECB(cipher, key)
	if !bytes.Equal(got, expected) {
		t.Errorf("DecryptAESECB did not decrypt correctly, expected %q got %q", expected, got)
	}

	got = matasano.EncryptAESECB(got, key)
	if !bytes.Equal(got, cipher) {
		t.Errorf("EncryptAESECB did not encrypt correctly, expected %q got %q", cipher, got)
	}
}

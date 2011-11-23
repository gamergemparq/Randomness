<?php

class RandomnessTest extends CTestCase {

	public function testPseudoRanBlock() {
		$s = Randomness::pseudoRanBlock();
		$this->assertNotEmpty($s);
		$this->assertInternalType('string', $s);
		$this->assertTrue(mb_strlen($s, 'ISO-8859-1') > 60);
	}

	public function testRandomBytes() {
		$s = Randomness::randomBytes(30);
		$this->assertNotEmpty($s);
		$this->assertInternalType('string', $s);
		$this->assertTrue(mb_strlen($s, 'ISO-8859-1') == 30);
	}

	public function testBlowfishSalt() {
		$s = Randomness::blowfishSalt();
		$this->assertNotEmpty($s);
		$this->assertInternalType('string', $s);
		$this->assertNotEmpty(preg_match('/^\$2a\$\d\d\$[\.\/0-9A-Za-z]{22}/', $s));
		$this->assertTrue(mb_strlen($s, 'ISO-8859-1') > 20);
	}

	public function testRandomString() {
		$s = Randomness::randomString(30);
		$this->assertNotEmpty($s);
		$this->assertInternalType('string', $s);
		$this->assertTrue(mb_strlen($s, 'ISO-8859-1') == 30);
	}

}
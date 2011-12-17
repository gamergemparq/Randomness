<?php

class RandomnessTest extends CTestCase {

    protected static function show($s) {
        $len = mb_strlen($s, 'ISO-8859-1');
        echo PHP_EOL;
        for($i = 0; $i < $len; ++$i) {
            $c = $s[$i];
            printf('%2x', ord($c));
        }
        echo PHP_EOL;
    }
    protected static function graph($s) {
        $len = mb_strlen($s, 'ISO-8859-1');
        echo PHP_EOL;
        for($i = 0; $i < $len; ++$i) {
            $c = ord($s[$i]);
            $x = chr(35 + floor($c / 64));
            $y = $c % 64;
            echo str_repeat(' ', $y) . $x . str_repeat(' ', 63 - $y) . '.' . PHP_EOL;
        }
        echo PHP_EOL;
    }
    public function testRandomBytes() {
        $s = Randomness::randomBytes(30);
        $this->assertNotEmpty($s);
        $this->assertInternalType('string', $s);
        $this->assertTrue(mb_strlen($s, 'ISO-8859-1') == 30);
    }

    public function testPseudoRanBlock() {
        $s = Randomness::pseudoRanBlock();
        $this->assertNotEmpty($s);
        $this->assertInternalType('string', $s);
        $this->assertTrue(mb_strlen($s, 'ISO-8859-1') > 60);
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

    public function testSessionBlock() {
        $s = Randomness::sessionBlock();
        $this->assertNotEmpty($s);
        $this->assertInternalType('string', $s);
        $this->assertEquals(mb_strlen($s, 'ISO-8859-1'), 16);
        echo self::graph($s);
    }

}
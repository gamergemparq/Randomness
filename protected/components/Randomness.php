<?php

class Randomness extends CApplicationComponent
{

	/**
	 * Generate a pseudo random block of data using several sources. Uses dreadful
	 * nonsense hackery but is possibly better than using only mt_rand which is
	 * unsuitable on its own.
	 * @return string of 64 pseudo random bytes
	 */
	public static function pseudoRanBlock() {
		Yii::log(
			'Using ' . get_class() . '::pseudoRanBlock non-ctypto_strong bytes',
			'warning', 'security');

		$r = array();

		// get some data from mt_rand
		for ($i = 0; $i < 16; ++$i)
			$r[] = pack('V', mt_rand(0, 0xffffffff));

		// numerical values in ps, uptime and iostat ought to be fairly
		// unpredictable, gather the non-zero digits from those
		foreach (array('ps', 'uptime', 'iostat') as $cmd) {
			exec($cmd, $s, $ret);
			if (is_array($s) && $s && !$ret)
				foreach ($s as $v)
					if (false !== preg_match_all('/[1-9]+/', $v, $m) && isset($m[0]))
						$r[] = implode('', $m[0]);
		}

		// gather the current time's microsecond part
		$r[] =substr(microtime(), 2, 6);

		// concatenate everything gathered, mixit with sha 512 and convert that
		// to a string of bytes
		$r = str_split(hash('sha512', implode($r)), 8);
		$s = '';
		foreach ($r as $v)
			$s .= pack('V', hexdec($v));
		return $s;
	}

	/**
	 * Generate a string of random raw (binary) bytes, trying to use a
	 * cryptographically secure source.
	 * @param int $length number of random bytes to return
	 * @param bool $http use the www.random.org http service
	 * @return string the random binary string
	 */
	public static function randomBytes($length = 8, $http = false) {
		$f = @fopen('/dev/random', 'r');
		if (function_exists('openssl_random_pseudo_bytes')) {
			$s = openssl_random_pseudo_bytes($length, $safe);
			if ($s !== false)
				if ($safe)
					return $s;
				elseif ($f === false) {
					Yii::log(
						'Using non-ctypto_strong bytes from openssl_random_pseudo_bytes',
						'warning', 'security');
					return $s;
				}
		}
		if ($f !== false) {
			$s = @fread($f, $length);;
			fclose($f);
		}
		if (mb_strlen($s, 'ISO-8859-1') < $length)
			$s = false;
		if (!$s && $http) {
			$r = @file_get_contents(
				'http://www.random.org/cgi-bin/randbyte?nbytes='
				. $length
				. '&format=f'
			);
			if ($r && ($rl = mb_strlen($r, 'ISO-8859-1')) >= $length)
				return $rl > $length
					? $r = mb_substr($r, 0, $length, 'ISO-8859-1')
					: $r;
		}
		if (!$s) {
			$s = '';
			do $s .= self::pseudoRanBlock();
			while (mb_strlen($s, 'ISO-8859-1') < $length);
		}
		if (mb_strlen($s, 'ISO-8859-1') > $length)
			$s = mb_substr($s, 0, $length, 'ISO-8859-1');
		return $s;
	}

	/**
	 * Generate a random Blowfish salt for use in PHP's crypt().
	 * @param $cost int cost parameter between 4 and 31
	 * @return string salt starting $2a$
	 */
	public static function blowfishSalt($cost = 10) {
		return '$2a$'
			. str_pad($cost, 2, '0', STR_PAD_RIGHT) . '$'
			. strtr(substr(base64_encode(
				self::randomBytes(18)
			), 0, 24), '+', '.');
	}

	/**
	 * Generate a random ASCII string using only [0-9a-zA-z~.]
	 * @param int $length length of the string in characters
	 * @return string the random string
	 */
	public static function randomString($length = 8) {
		return strtr(substr(base64_encode(
				self::randomBytes($length + 2)
			), 0, $length), '+/', '~.');
	}

}
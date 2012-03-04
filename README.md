Randomness
==========

The static object Randomness is a collection of helper methods for web apps that need
random data for security purposes.

Cryptographically-secure random data
------------------------------------

Applications may require Cryptographically Secure (CS) random data
[Wikipedia CSPRNG](http://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)
to be used in forming, for example, encryption keys, random passwords, session keys,
stream initialization vectors, nonces, secure unique IDs, and some kinds of salts.

PHP's mt_rand is a simple pseudo-random number gnerator designed
for use in Monte Carlo simulations, not in security systems. It is not
cryptographically secure. You can determine the next random
number from previous ones or from knowing the internal state of the generator.

Most operating systems on which PHP typically runs provide a CSPRNG as a service to
applications. On Windows it is called
[CryptGenRandom](http://msdn.microsoft.com/en-us/library/aa379942.aspx).
On Linux, OS X, FreeBSD etc.
applications may read the /dev/random pseudo-device. Each of these OSs also offers a
way for the user to query the status of the CSPRNG. But in PHP, accessing the CSPRNG
can be problematic.

`Randomness::randomBytes` uses several different approaces to read from
the operating system's CSPRNG. It is possible that all of them may fail. In this
case it has an option to get data from the http://www.random.org service and another
option to fall back on its own non-crypto-secure generator.

Storing passwords in web apps
-----------------------------

There are many tutorials and examples that show storage of passwords in a table.
Often the methods used are substandard and very easy to crack. For example, the
"Agile Yii" book's example stores md5($password) in the DB and calls it
"encryption". It is not. "The Definitive Guide to Yii" is a little better in
that it uses a salt but it still uses md5 and is easy to crack.

You cannot rely on a user to use a (practically) unguessable password or to not
use that password in systems other than yours. And you should not assume that
your server is so secure that an attacker cannot get hold of the password file.

So you use a salt to ensure that the hash is unlikely to appear in any
dictionary or rainbow. But this is not enough. First, each password needs its own
random salt. Second, the hash function needs to be slow to calculate (computationally
expensive, as the techies say).

The second problem is fast hashes. MD5, for example, is very fast. As of Nov
2011 you can check 350 million keys per second on a commodity nVidia processor.
So no matter what you do with salts, the combination of short passwords and fast
brute force checking means your system is open to intruders if you rely on a
non-iterated message digest such as md5, SHA and the rest.

Blowfish is currently considered pretty good. It is designed to be slow. The
implementation in PHP's `crypt()` is easy to use. Set a cost parameter high enough
to make a brute force attack really slow. I set it so that it takes about 250 ms
on the production server (a completely arbitrary choice:-).

Each password should have its own random salt. The salt's purpose is to make the
dictionary size in a rainbow or dictionary attack so large that the attack is not
feasible. Salts used with the Blowfish hash do not need to be
cryptographically secure random strings so Randomness's salt generator by default
uses the casses pseudo-random generator.

Some people advocate resalting every time a user logs in. I think this is only
useful if you also limit the time interval between user logins, e.g. block an
account if the user hasn't logged in in more than N weeks.


Using PHP's crypt() to store passwords
--------------------------------------

People often get confused about how to use implement a password store using `crypt()`.
It is actually very simple but it helps to know that:

* It is safe to store the salt together with the password hash. An attacker cannot use
it to make a dictionary attack easier.

* The string `crypt()` returns is the concatenation of the salt you give it and the
hash value.

* `crypt()` ignores excess characters in the input salt string.

`crypt()` has function signature `string crypt (string $str, string $salt)` and the
salt string format determines the hash method. For Blowfish hashing, the format is:
`"$2a$"`, a two digit cost parameter, `"$"`, and 22 digits from the alphabet
`"./0-9A-Za-z"`. The cost must be between `04` and `31`.

```php
crypt('EgzamplPassword', '$2a$10$1qAz2wSx3eDc4rFv5tGb5t')
>> '$2a$10$1qAz2wSx3eDc4rFv5tGb5e4jVuld5/KF2Kpy.B8D2XoC031sReFGi'
```

The first 29 characters are the same as the salt string. Anthing appended to the salt
string argument has no effect on the result:

```php
crypt('EgzamplPassword', '$2a$10$1qAz2wSx3eDc4rFv5tGb5t12345678901234567890')
>> '$2a$10$1qAz2wSx3eDc4rFv5tGb5e4jVuld5/KF2Kpy.B8D2XoC031sReFGi'

crypt('EgzamplPassword', '$2a$10$1qAz2wSx3eDc4rFv5tGb5t$2a$10$1qAz2wSx3eDc4rFv5tGb5t')
>> '$2a$10$1qAz2wSx3eDc4rFv5tGb5e4jVuld5/KF2Kpy.B8D2XoC031sReFGi'

And in particular:
crypt('EgzamplPassword', '$2a$10$1qAz2wSx3eDc4rFv5tGb5e4jVuld5/KF2Kpy.B8D2XoC031sReFGi')
>> '$2a$10$1qAz2wSx3eDc4rFv5tGb5e4jVuld5/KF2Kpy.B8D2XoC031sReFGi'
```

So we can use `crypt()` to authenticate a user by passing the hash value it
gave us previously back in as a salt when checking a user salt input.

Example
-------

Say we have a `user` table like this

```sql
create table user (
  id int not null auto_increment primary key,
  email varchar(255) not null,
  password_hash char(50) not null,
  unique key (email)
)
```

From a user account generation form we have (already sanitized) user input in
$form->email and $form->password. We henerate the hash:

```php
$password_hash = crypt($form->password, Randomness::blowfishSalt());
```

And insert a row into `user` containing $form->email and $password_hash.

At user logon we again have sanitized user input in $form->email and $form->password.
To authenticate these against the accounts in `user` we select the password_hash from
user where email = $form->email and

```php
if ($password_hash === crypt($form->password, $password_hash))
	// password is correct
else
	// password is wrong
```

So there is no need to store the salt in a separate column from the hash value because
`crypt()` lets us keep it in the same string as the hash.

In Yii
------

`Randomness::blowfishSalt()` generates a salt to use with `crypt()`, for example:

    $user = new User;
    $user->email = $form->email;
    $user->bf_hash = crypt($form->password, Randomness::blowfishSalt());
    if ($user->save())
        ...

To authenticate:

    public function authenticate() {
        $user = User::model()->findByAttributes(array(
            'email' => $this->username,
        ));
        if ($user === null
            || crypt($this->password, $user->bf_hash) !== $user->bf_hash
        )
            $this->errorCode = self::ERROR_UNKNOWN_IDENTITY;
        ...


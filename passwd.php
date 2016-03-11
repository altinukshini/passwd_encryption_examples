<?php

$mypassword = 'mypassword';
echo $mypassword."<br/>";

// MD5 based examples below

$password1 = crypt($mypassword);
echo 'password1:          ' . $password1 . "<br>"; // Random salt, crypt() uses system default hashing algorithm (most commonly DES or MD5)

$password2 = encryptPassword('md5', $mypassword);
echo 'password2:          ' . $password2 . "<br>"; // Random salt

$password3 = crypt($mypassword, '$1$somesalt134$'); // Anything between $1$...$ gets trimmed to 8 characters only, that's how MD5 works...
echo 'password3:          ' . $password3 . "<br>";

$password4 = mycrypt($mypassword, 'somesalt'); // Salt must be 8 chars long for MD5
echo 'password4:          ' . $password4 . "<br>";

$password5 = crypt($mypassword, '$1$'.md5($mypassword).'$'); // Even though we're using md5(), crypt() in this case trims it to 8 chars only
echo 'password5:          ' . $password5 . "<br>";

$password6 = mycrypt($mypassword, substr(md5($mypassword), 0,8)); // When using mycrypt(), trim it yourself
// $password6 = mycrypt($mypassword, md5($mypassword)); // this will not work
echo 'password6:          ' . $password6 . "<br>"; // same as $password5

$password7 = crypt($mypassword, '$1$'.md5('username').'$'); // you could use username's md5() hash as salt
echo 'password7:          ' . $password7 . "<br>";


echo '<br>';
echo '<br>';


// Comparison of two encrypted passwords
if (hash_equals($password1, crypt($mypassword, $password1))) {
   echo "Password verified!";
}



// A good hash comparison function taken from WP: https://developer.wordpress.org/reference/functions/hash_equals/
function hash_equals( $a, $b ) 
{
    $a_length = strlen( $a );
    if ( $a_length !== strlen( $b ) ) {
        return false;
    }
    $result = 0;
 
    // Do not attempt to "optimize" this.
    for ( $i = 0; $i < $a_length; $i++ ) {
        $result |= ord( $a[ $i ] ) ^ ord( $b[ $i ] );
    }
 
    return $result === 0;
}

// Could be used for DES, SHA256 and SHA512
function encryptPassword($crypt_hash,$passwd)
{
  $salt = '';
  switch ($crypt_hash) {
  case 'md5':
	  $len = 8;
	  $salt_hashindicator = '$1$';
	  break;
  case 'des':
	  $len = 2;
	  break;
  case 'sha256':
	  $len = 16;
	  $salt_hashindicator = '$5$';
	  break;
  case 'sha512':
	  $len = 16;
	  $salt_hashindicator = '$6$';
	  break;
  }
  //Restrict the character set used as salt (#1488136)
  $seedchars = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  for ($i = 0; $i < $len ; $i++) {
	  $salt .= $seedchars[rand(0, 63)];
  }
  return crypt($passwd, $salt_hashindicator ? $salt_hashindicator .$salt.'$' : $salt);
}

function to64($s, $n)
{
    $i64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    $r = '';
    while (--$n >= 0) {
        $ss = $s & 0x3f;
        $r .= $i64[$s & 0x3f];
        $s >>= 6;
     }
    return $r;
}

function mycrypt($password, $salt) 
{
    $m = hash_init("md5");
    hash_update($m, $password);
    hash_update($m, '$1$');
    hash_update($m, $salt);

    $m1 = hash_init("md5");
    hash_update($m1, $password);
    hash_update($m1, $salt);
    hash_update($m1, $password);
    $final = hash_final($m1, true);
    for ($pl = strlen($password); $pl>0; $pl-=16) {
            hash_update($m, substr($final, 0, $pl > 16? 16:$pl));
    }
    $final = "\0";
    for($i=strlen($password);$i!=0;$i>>=1) {
            if (($i & 1) != 0) {
                    hash_update($m, $final);
            } else {
                    hash_update($m, $password[0]);
           }
    }
    $final = hash_final($m, true);
    for($i=0;$i<1000;$i++) {
        $m1 = hash_init("md5");

        if(($i&1)) {
            hash_update($m1, $password);
        } else {
            hash_update($m1, $final);
        }
        if(($i%3)) {
            hash_update($m1, $salt);
        }
        if(($i%7)) {
            hash_update($m1, $password);
        }
        if(($i&1)) {
            hash_update($m1, $final);
        } else {
            hash_update($m1, $password);
        }
        $final = hash_final($m1, true);
    }
    $l = '$1$'.$salt.'$';
    $l .= to64(ord($final[ 0])<<16 | (ord($final[ 6])<<8) | ord($final[12]), 4);
    $l .= to64(ord($final[ 1])<<16 | (ord($final[ 7])<<8) | ord($final[13]), 4);
    $l .= to64(ord($final[ 2])<<16 | (ord($final[ 8])<<8) | ord($final[14]), 4);
    $l .= to64(ord($final[ 3])<<16 | (ord($final[ 9])<<8) | ord($final[15]), 4);
    $l .= to64(ord($final[ 4])<<16 | (ord($final[10])<<8) | ord($final[ 5]), 4);
    $l .= to64(ord($final[11]), 2);

    return $l;
}

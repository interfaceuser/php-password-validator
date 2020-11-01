<?php

require "../src/PasswordValidator.php";

use PHPPasswordValidator\PasswordValidator ;

$data = new PasswordValidator([
    'lang' => 'en',
    'containNumbers' => true,
    'minLength' => 2,
    'maxLength' => 10,
    'containLetters' => true
]);
echo '<pre>';
print_r($data->validate('1234 5'));
echo '</pre>';

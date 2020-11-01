<?php

namespace Php\Password\Validator\Tests;

require __DIR__ . "/../src/PasswordValidator.php";

use Php\Password\Validator\PasswordValidator;
use PHPUnit\Framework\TestCase;

class PasswordValidatorTest extends TestCase
{

    public function testValidate()
    {
        $defaultSettings = new PasswordValidator();
        $this->assertEquals([], $defaultSettings->validate('12346578'));

        $minLength = new PasswordValidator(['minLength' => 5]);
        $minLengthExpected = ['minLength' => 'Minimum password length is 5 character(s).'];
        $this->assertEquals($minLengthExpected, $minLength->validate('1234'));

        $maxLength = new PasswordValidator(['maxLength' => 5]);
        $MaxLengthExpected = ['maxLength' => 'Maximum password length is 5 character(s).'];
        $this->assertEquals($MaxLengthExpected, $maxLength->validate('123456789'));

        $containNumbers = new PasswordValidator(['containNumbers' => true]);
        $containNumbersExpected = ['containNumbers' => 'Password should contain at least one number.'];
        $this->assertEquals($containNumbersExpected, $containNumbers->validate('qwerty'));

        $minNumbers = new PasswordValidator(['minNumbers' => 3]);
        $minNumbersExpected = ['minNumbers' => 'The minimum number of digits in a password is 3. You have 2.'];
        $this->assertEquals($minNumbersExpected, $minNumbers->validate('qw1er2ty'));

        $maxNumbers = new PasswordValidator(['maxNumbers' => 5]);
        $maxNumbersExpected = ['maxNumbers' => 'The maximum number of digits in a password is 5. You have 6.'];
        $this->assertEquals($maxNumbersExpected, $maxNumbers->validate('qw1er2ty3456'));

        $containLetters = new PasswordValidator(['containLetters' => true]);
        $containLettersExpected = ['containLetters' => 'Password should contain at least one letter.'];
        $this->assertEquals($containLettersExpected, $containLetters->validate('123456789'));

        $minLetters = new PasswordValidator(['minLetters' => 5]);
        $minLettersExpected = ['minLetters' => 'The minimum number of letters in a password is 5. You have 4.'];
        $this->assertEquals($minLettersExpected, $minLetters->validate('123456qwer'));

        $maxLetters = new PasswordValidator(['maxLetters' => 2]);
        $maxLettersExpected = ['maxLetters' => 'The maximum number of letters in a password is 2. You have 4.'];
        $this->assertEquals($maxLettersExpected, $maxLetters->validate('123456qwer'));

        $lowerLetters = new PasswordValidator(['lowerLetters' => true]);
        $lowerLettersExpected = ['lowerLetters' => 'Password must contain at least one lowercase letter.'];
        $this->assertEquals($lowerLettersExpected, $lowerLetters->validate('123456QWER'));

        $upperLetters = new PasswordValidator(['upperLetters' => true]);
        $upperLettersExpected = ['upperLetters' => 'Password must contain at least one uppercase letter.'];
        $this->assertEquals($upperLettersExpected, $upperLetters->validate('123456qwer'));

        $containSymbols = new PasswordValidator(['containSymbols' => true]);
        $containSymbolsExpected = ['containSymbols' => 'Password should contain at least one symbol.'];
        $this->assertEquals($containSymbolsExpected, $containSymbols->validate('123456qwer'));

        $availableSymbols = new PasswordValidator(['availableSymbols' => '/*-']);
        $availableSymbolsExpected = ['availableSymbols' => 'You are using prohibited characters. The list of allowed characters /*-.'];
        $this->assertEquals($availableSymbolsExpected, $availableSymbols->validate('123456qwer()'));

        $availableSpaces = new PasswordValidator(['availableSpaces' => false]);
        $availableSpacesExpected = ['availableSpaces' => 'Password cannot contain spaces.'];
        $this->assertEquals($availableSpacesExpected, $availableSpaces->validate('123456 qwer'));

        $multiParameters = new PasswordValidator([
            'minNumbers' => 5,
            'upperLetters' => true,
            'availableSymbols' => '/*-'
        ]);
        $multiParametersExpected = [
            'upperLetters' => 'Password must contain at least one uppercase letter.',
            'availableSymbols' => 'You are using prohibited characters. The list of allowed characters /*-.',
            'availableSpaces' => 'Password cannot contain spaces.'
        ];
        $this->assertEquals($multiParametersExpected, $multiParameters->validate('123456 qwer()'));

        $checkRussianTransale = new PasswordValidator(['lang' => 'ru', 'minLength' => 10]);
        $checkRussianTransaleExpected = ['minLength' => 'Минимальная длина пароля 10 символ(ов).'];
        $this->assertEquals($checkRussianTransaleExpected, $checkRussianTransale->validate('123456'));
    }
}

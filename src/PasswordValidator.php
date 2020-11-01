<?php


namespace PHPPasswordValidator;


class PasswordValidator
{
    private $options = [
        'lang' => 'en',
        'minLength' => 5,
        'maxLength' => INF,
        'containNumbers' => false,
        'minNumbers' => 0,
        'maxNumbers' => INF,
        'containLetters' => false,
        'minLetters' => 0,
        'maxLetters' => INF,
        'lowerLetters' => false,
        'upperLetters' => false,
        'containSymbols' => false,
        'availableSymbols' => '+-*$#@!%:?',
        'availableSpaces' => false,
    ];

    /**
     * PasswordValidator constructor.
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        if (!empty($options)) {
            $newOptions = array_merge($this->options, $options);
            $this->options = $newOptions;
        }
    }

    /**
     * Return error, based on options language
     * @param string $error
     * @param string $subject
     * @return string
     */
    private function getError($error, $subject = ''): string
    {
       $errors = [
           'en' => [
               'minLength' => str_replace(
                   '#minlength#',
                   $this->options['minLength'],
                   'Minimum password length is #minlength# character(s).'
               ),
               'maxLength' => str_replace(
                   '#maxlength#',
                   $this->options['maxLength'],
                   'Maximum password length is #maxlength# character(s).'
               ),
               'containNumbers' => 'Password should contain at least one number.',
               'minNumbers' => str_replace(
                   ['#minnumbers#', '#countnumbers#'],
                   [$this->options['minNumbers'], self::countNumbers($subject)],
                   'The minimum number of digits in a password is #minnumbers#. You have #countnumbers#.'
               ),
               'maxNumbers' => str_replace(
                   ['#maxnumbers#', '#countnumbers#'],
                   [$this->options['maxNumbers'], self::countNumbers($subject)],
                   'The maximum number of digits in a password is #maxnumbers#. You have #countnumbers#.'
               ),
               'containLetters' => 'Password should contain at least one letter.',
               'minLetters' => str_replace(
                   ['#minletters#', '#countletters#'],
                   [$this->options['minLetters'], self::countLetters($subject)],
                   'The minimum number of letters in a password is #minletters#. You have #countletters#.'
               ),
               'maxLetters' => str_replace(
                   ['#maxletters#', '#countletters#'],
                   [$this->options['maxLetters'], self::countLetters($subject)],
                   'The maximum number of letters in a password is #maxletters#. You have #countletters#.'
               ),
               'lowerLetters' => 'Password must contain at least one lowercase letter.',
               'upperLetters' => 'Password must contain at least one uppercase letter.',
               'containSymbols' => 'Password should contain at least one symbol.',
               'availableSymbols' => str_replace(
                   '#availablesymbols#',
                   $this->options['availableSymbols'],
                   'You are using prohibited characters. The list of allowed characters #availablesymbols#.'
               ),
               'availableSpaces' => 'Password cannot contain spaces.',
           ],
           'ru' => [
               'minLength' => str_replace(
                   '#minlength#',
                   self::rusWordForm($this->options['minLength'], ['символ', 'символа', 'символов']),
                   'Минимальная длина пароля #minlength#.'
               ),
               'maxLength' => str_replace(
                   '#maxlength#',
                   self::rusWordForm($this->options['maxLength'], ['символ', 'символа', 'символов']),
                   'Максимальная длина пароля #maxlength#.'
               ),
               'containNumbers' => 'Пароль должен содержать хотя бы одну цифру.',
               'minNumbers' => str_replace(
                   ['#minnumbers#', '#countnumbers#'],
                   [$this->options['minNumbers'], self::countNumbers($subject)],
                   'Минимальное количество цифр в пароле должно быть #minnumbers#. У Вас #countnumbers#.'
               ),
               'maxNumbers' => str_replace(
                   ['#maxnumbers#', '#countnumbers#'],
                   [$this->options['maxNumbers'], self::countNumbers($subject)],
                   'Максимальное количество цифр в пароле должно быть #maxnumbers#. У Вас #countnumbers#.'
               ),
               'containLetters' => 'Пароль должен содержать хотя бы одну букву.',
               'minLetters' => str_replace(
                   ['#minletters#', '#countletters#'],
                   [$this->options['minLetters'], self::countLetters($subject)],
                   'Минимальное количество букв в пароле #minletters#. У Вас #countletters#.'
               ),
               'maxLetters' => str_replace(
                   ['#maxletters#', '#countletters#'],
                   [$this->options['maxLetters'], self::countLetters($subject)],
                   'Максимальное количество букв в пароле #maxletters#. У Вас #countletters#.'
               ),
               'lowerLetters' => 'В пароле должна быть хотя бы одна буква в нижнем регистре.',
               'upperLetters' => 'В пароле должна быть хотя бы одна буква в верхнем регистре.',
               'containSymbols' => 'Пароль должен содержать хотя бы один символ.',
               'availableSymbols' => str_replace(
                   '#availablesymbols#',
                   $this->options['availableSymbols'],
                   'Вы используйте запрещенные символы. Список разрешенных символов #availablesymbols#.'
               ),
               'availableSpaces' => 'Пароль не может содержать пробелы.',
           ],
       ];

        return (isset($errors[$this->options['lang']][$error])) ? $errors[$this->options['lang']][$error] : $errors['en'][$error];
    }


    /**
     * Return form of russian words after numbers.
     * @param int $num
     * @param array $words
     * @return string
     */
    private function rusWordForm(int $num, array $words): string
    {
        $num = abs($num) % 100;
        $num_x = $num % 10;
        if ($num > 10 && $num < 20) {
            return $num . ' '. $words[2];
        }
        if ($num_x > 1 && $num_x < 5) {
            return $num . ' '. $words[1];
        }
        if ($num_x == 1) {
            return $num . ' '. $words[0];
        }
        return $num . ' '. $words[2];
    }

    /**
     * Checking minimum length of password
     * @param string $subject
     * @return bool
     */
    private function checkMinLength(string $subject): bool
    {
        return strlen($subject) >= $this->options['minLength'];
    }

    /**
     * Checking maximum length of password
     * @param string $subject
     * @return bool
     */
    private function checkMaxLength(string $subject): bool
    {
        return strlen($subject) <= $this->options['maxLength'];
    }

    /**
     * Checking for digits in a string
     * @param string $subject
     * @return bool
     */
    private function hasNumber(string $subject): bool
    {
        return strpbrk($subject, '1234567890') !== false;
    }

    /**
     * Counts the number of digits
     * @param string $subject
     * @return int
     */
    private function countNumbers(string $subject): int
    {
        return strlen(preg_replace( '/[^0-9]/', '', $subject));
    }

    /**
     * Checking the minimum number of digits in a password
     * @param string $subject
     * @return bool
     */
    private function checkMinNumbers(string $subject): bool
    {
        return self::countNumbers($subject) >= $this->options['minNumbers'];
    }

    /**
     * Checking the maximum number of digits in a password
     * @param string $subject
     * @return bool
     */
    private function checkMaxNumbers(string $subject): bool
    {
        return self::countNumbers($subject) <= $this->options['maxNumbers'];
    }

    /**
     * Count letters in password
     * Function can count lowercase, uppercase or all letters (2nd parameter)
     * @param string $subject
     * @param string $type
     * @return int
     */
    private function countLetters(string $subject, string $type = "all"): int
    {
        if ($type == 'lower') {
            $pattern = '/[^a-z]+/';
        } elseif ($type == 'upper') {
            $pattern = '/[^A-Z]+/';
        } else {
            $pattern = '/[^a-zA-Z]+/';
        }

        return strlen(preg_replace( $pattern, '', $subject));
    }

    /**
     * Checking letters in password
     * @param string $subject
     * @return bool
     */
    private function hasLetters(string $subject): bool
    {
        return self::countLetters($subject) > 0;
    }

    /**
     * Checking the minimum number of letters in a password
     * @param string $subject
     * @return bool
     */
    private function checkMinLetters(string $subject): bool
    {
        return self::countLetters($subject) >= $this->options['minLetters'];
    }

    /**
     * Checking the maximum number of letters in a password
     * @param string $subject
     * @return bool
     */
    private function checkMaxLetters(string $subject): bool
    {
        return self::countLetters($subject) <= $this->options['maxLetters'];
    }

    /**
     * Checking if password contains lowercase letters
     * @param string $subject
     * @return bool
     */
    private function hasLowerLetters(string $subject): bool
    {
        return self::countLetters($subject, 'lower') > 0;
    }

    /**
     * Checking if password contains uppercase letters
     * @param string $subject
     * @return bool
     */
    private function hasUpperLetters(string $subject): bool
    {
        return self::countLetters($subject, 'upper') > 0;
    }

    /**
     * Checking password contains symbols
     * @param string $subject
     * @return bool
     */
    private function hasSymbols(string $subject): bool
    {
        if (empty($this->options['availableSymbols'])) { return false; }
        return strpbrk($subject, $this->options['availableSymbols']) !== false;
    }

    /**
     * Checking if password contains permitted symbols
     * @param string $subject
     * @return bool
     */
    private function checkPermittedSymbols(string $subject): bool
    {
        $availableSymbols = str_split($this->options['availableSymbols']);
        $onlySymbols = preg_replace('/[ a-zA-Z0-9]/', '', $subject);
        if (empty($onlySymbols)) {
            return true;
        }
        $result = true;
        for ($i = 0; $i < strlen($onlySymbols); $i++) {
            if (!in_array($onlySymbols[$i], $availableSymbols)) {
                $result = false;
            }
        }
        return $result;
    }

    /**
     * Checking spaces in password
     * @param string $subject
     * @return bool
     */
    private function hasSpaces(string $subject)
    {
        return strpos($subject, ' ') !== false;
    }

    /**
     * Validate passwords.
     * If no errors in password - return empty array.
     * If password has errors - return array with errors
     * @param string $subject
     * @return array
     */
    public function validate(string $subject): array
    {
        $subject = trim($subject);
        $errors = [];

        // Min length
        if (isset($this->options['minLength'])) {
            if (!self::checkMinLength($subject)) {
                $errors['minLength'] = self::getError('minLength');
            }
        }

        // Max Length
        if (isset($this->options['maxLength'])) {
            if (!self::checkMaxLength($subject)) {
                $errors['maxLength'] = self::getError('maxLength');
            }
        }

        // Contain numbers
        if (isset($this->options['containNumbers']) && $this->options['containNumbers']) {
            if (!self::hasNumber($subject)) {
                $errors['containNumbers'] = self::getError('containNumbers');
            }
        }

        // Min numbers
        if (isset($this->options['minNumbers'])) {
            if (!self::checkMinNumbers($subject)) {
                $errors['minNumbers'] = self::getError('minNumbers', $subject);
            }
        }

        // Max numbers
        if (isset($this->options['maxNumbers'])) {
            if (!self::checkMaxNumbers($subject)) {
                $errors['maxNumbers'] = self::getError('maxNumbers', $subject);
            }
        }

        // Contain letters
        if (isset($this->options['containLetters']) && $this->options['containLetters']) {
            if (!self::hasLetters($subject)) {
                $errors['containLetters'] = self::getError('containLetters');
            }
        }

        // Min letters
        if (isset($this->options['minLetters'])) {
            if (!self::checkMinLetters($subject)) {
                $errors['minLetters'] = self::getError('minLetters', $subject);
            }
        }

        // Max letters
        if (isset($this->options['maxLetters'])) {
            if (!self::checkMaxLetters($subject)) {
                $errors['maxLetters'] = self::getError('maxLetters', $subject);
            }
        }

        // Contain lower letters
        if (isset($this->options['lowerLetters']) && $this->options['lowerLetters']) {
            if (!self::hasLowerLetters($subject)) {
                $errors['lowerLetters'] = self::getError('lowerLetters');
            }
        }

        // Contain upper letters
        if (isset($this->options['upperLetters']) && $this->options['upperLetters']) {
            if (!self::hasUpperLetters($subject)) {
                $errors['upperLetters'] = self::getError('upperLetters');
            }
        }

        // Contain symbols
        if (isset($this->options['containSymbols']) && $this->options['containSymbols']) {
            if (!self::hasSymbols($subject)) {
                $errors['containSymbols'] = self::getError('containSymbols');
            }
        }

        // Contain permitted symbols
        if (isset($this->options['availableSymbols']) && !empty($this->options['availableSymbols'])) {
            if (!self::checkPermittedSymbols($subject)) {
                $errors['availableSymbols'] = self::getError('availableSymbols', $subject);
            }
        }

        // Contain spaces
        if (isset($this->options['availableSpaces']) && !$this->options['availableSpaces']) {
            if (self::hasSpaces($subject)) {
                $errors['availableSpaces'] = self::getError('availableSpaces');
            }
        }

        return $errors;
    }
}
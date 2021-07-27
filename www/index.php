<?php

date_default_timezone_set('America/Sao_Paulo');

class JWT {
    private $secret_key;
    
    function __construct($secret_key){
        $this->secret_key = $secret_key;
    }

    public function generate($payload)
    {
        $header = [
            'typ' => 'JWT', 
            'alg' => 'HS256'
        ];

        $header = $this->base64Url(json_encode($header));
        $payload = $this->base64Url(json_encode($payload));

        $signature = $this->base64Url(hash_hmac('sha256',"$header.$payload",$this->secret_key,true));

        return [
            'token'         =>  "$header.$payload.$signature"
        ];
    }

    private function base64Url($string)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    public function decode($string)
    {
        $message_response = '';

        $array = explode('.',$string);
        $header = $array[0];
        $payload = $array[1];
        $signature = $array[2];

        $signatureGenerated = $this->base64Url(hash_hmac('sha256',"$header.$payload",$this->secret_key,true));

        $verifySignature = $signature == $signatureGenerated ? true : false;

        $verifySignature ? $message_response = 'token is valid' : $message_response = 'token not valid';

        $payloadDecode = json_decode(base64_decode($payload),true);

        $now = new DateTime();
        if (isset($payloadDecode['exp'])) {
            if (!($now->getTimestamp() < $payloadDecode['exp'] )) {
                $message_response = 'token inspired';
                $verifySignature = false;
            }
        }

        return json_encode([
            'valid' => $verifySignature,
            'response' => [
                'message' => $message_response,
                'payload' => json_decode(base64_decode($payload)),
            ]
        ]);

    }

}

$jwt = new JWT('secret_key');

$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjMsImV4cCI6MTYyNzM3NzYwMH0.3IrNeZ0JXInRQ7BZQM2TbVrvQeyYzQUe7ZfoOJEk8uA';
echo $jwt->decode($token);

// echo json_encode($jwt->generate([
//         'user_id' => 123,
//         'exp'     => strtotime('2021-07-27 06:20'),
//     ]));
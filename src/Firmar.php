<?php 

namespace Josefranciscocruzcorro\Firmador;

use Exception;

class Firmar 
{
    private $xml;
    private $p12_path;
    private $p12_pass;

    private $archivo;

    private $certificados;
    private $privateKey;
    private $public_key;

    private $signTime = null;
    private $certificate = null;
    private $certData = null;
    private $tipoComprobante = null;
    private $claveAcceso = null;

    private $config;

    private $signatureID;
    private $signedInfoID;
    private $signedPropertiesID;
    private $signatureValueID;
    private $certificateID;
    private $referenceID;
    private $signatureSignedPropertiesID;
    private $signatureObjectID;

    function __construct($p12_path,$p12_pass,$xml,$claveAcceso)
    {
        # code...
        $this->xml = $xml;
        $this->p12_path = $p12_path;
        $this->p12_pass = $p12_pass;

        $this->claveAcceso = $claveAcceso;

        $this->tipoComprobante = substr($this->claveAcceso, 8, 2);

        $this->config = array(
            'file' => null,
            'pass' => null,
            'wordwrap' => 64,
        );

        $this->setCertficado();
    }

    public function setCertficado()
    {
        if (!$this->archivo = file_get_contents($this->p12_path)) {
            # code...
            echo "No es posible leer el certificado.";
        } else {
            # code...
            if(!openssl_pkcs12_read($this->archivo,$this->certificados,$this->p12_pass)){
                echo "Error al intentar obtener los certificados.";
            }else{
                
                if (!$this->privateKey = openssl_pkey_get_private($this->certificados['pkey'],$this->p12_pass)) {
                    # code...
                    echo "Error al intentar obtener la clave privada.";
                } else {
                    # code...
                    if (!$this->public_key = openssl_pkey_get_public($this->certificados['cert'])) {
                        # code...
                        echo "Error al intentar obtener la clave pública.";
                    }else{
                        $x509cert = openssl_x509_read($this->certificados['cert']);
                        $certData = openssl_x509_parse($x509cert);
                        $this->certificate = $x509cert;
                        $this->certData = $certData;

                    }
                }                
            }
        }
    }

    public function generarId()
    {

        // Generate random IDs
        $this->signatureID = $this->random();
        $this->signedInfoID = $this->random();
        $this->signedPropertiesID = $this->random();
        $this->signatureValueID = $this->random();
        $this->certificateID = $this->random();
        $this->referenceID = $this->random();
        $this->signatureSignedPropertiesID = $this->random();
        $this->signatureObjectID = $this->random();

    }

    private function random()
    {
        return rand(100000, 999999);
    }


    public function firmar()
    {
        $respuesta = null;
        
        try {

            if (empty($this->public_key) || empty($this->privateKey)) return $this->xml;

            $xml = $this->xml;

            $xmlns = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"';

            $signTime = is_null($this->signTime) ? time() : $this->signTime;
            $certDigest = $this->getcertDigest();
            $certIssuer = $this->getIssuer();
            $serialNumber = $this->getSerial();

            $prop = '<etsi:SignedProperties Id="Signature' . $this->signatureID .
                '-SignedProperties' . $this->signatureSignedPropertiesID . '">' .
                '<etsi:SignedSignatureProperties>' .
                '<etsi:SigningTime>' . date('c', $signTime) . '</etsi:SigningTime>' .
                '<etsi:SigningCertificate>' .
                '<etsi:Cert>' .
                '<etsi:CertDigest>' .
                '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>' .
                '<ds:DigestValue>' . $certDigest . '</ds:DigestValue>' .
                '</etsi:CertDigest>' .
                '<etsi:IssuerSerial>' .
                '<ds:X509IssuerName>' . $certIssuer . '</ds:X509IssuerName>' .
                '<ds:X509SerialNumber>' . $serialNumber . '</ds:X509SerialNumber>' .
                '</etsi:IssuerSerial>' .
                '</etsi:Cert>' .
                '</etsi:SigningCertificate>' .
                '</etsi:SignedSignatureProperties>' .
                '<etsi:SignedDataObjectProperties>' .
                '<etsi:DataObjectFormat ObjectReference="#Reference-ID-' . $this->referenceID . '">' .
                '<etsi:Description>contenido comprobante</etsi:Description>' .
                '<etsi:MimeType>text/xml</etsi:MimeType>' .
                '</etsi:DataObjectFormat>' .
                '</etsi:SignedDataObjectProperties>' .
                '</etsi:SignedProperties>';


            $modulus = $this->getModulus();

            $exponent = $this->getExponent();

            $publicPEM = $this->public_key;

            $kInfo = '<ds:KeyInfo Id="Certificate' . $this->certificateID . '">' . "\n" .
                '<ds:X509Data>' . "\n" .
                '<ds:X509Certificate>' . "\n" . $publicPEM . "\n" . '</ds:X509Certificate>' . "\n" .
                '</ds:X509Data>' . "\n" .
                '<ds:KeyValue>' . "\n" .
                '<ds:RSAKeyValue>' . "\n" .
                '<ds:Modulus>' . "\n" . $modulus . "\n" . '</ds:Modulus>' . "\n" .
                '<ds:Exponent>' . $exponent . '</ds:Exponent>' . "\n" .
                '</ds:RSAKeyValue>' . "\n" .
                '</ds:KeyValue>' . "\n" .
                '</ds:KeyInfo>';

            $propDigest = base64_encode(sha1(str_replace('<etsi:SignedProperties',
                '<etsi:SignedProperties ' . $xmlns, $prop), true));

            $aux = str_replace('<ds:KeyInfo', '<ds:KeyInfo ' . $xmlns, $kInfo);

            $kInfoDigest = base64_encode(sha1($aux, true));

            $documentDigest = base64_encode(sha1($xml, true));

            

            $sInfo = '<ds:SignedInfo Id="Signature-SignedInfo' . $this->signedInfoID . '">' . "\n" .
                '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">' .
                '</ds:CanonicalizationMethod>' . "\n" .
                '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1">' .
                '</ds:SignatureMethod>' . "\n" .
                '<ds:Reference Id="SignedPropertiesID' . $this->signedPropertiesID . '" ' .
                'Type="http://uri.etsi.org/01903#SignedProperties" ' .
                'URI="#Signature' . $this->signatureID . '-SignedProperties' .
                $this->signatureSignedPropertiesID . '">' . "\n" .
                '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">' .
                '</ds:DigestMethod>' . "\n" .
                '<ds:DigestValue>' . $propDigest . '</ds:DigestValue>' . "\n" .
                '</ds:Reference>' . "\n" .
                '<ds:Reference URI="#Certificate' . $this->certificateID . '">' . "\n" .
                '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">' .
                '</ds:DigestMethod>' . "\n" .
                '<ds:DigestValue>' . $kInfoDigest . '</ds:DigestValue>' . "\n" .
                '</ds:Reference>' . "\n" .
                '<ds:Reference Id="Reference-ID-' . $this->referenceID . '" URI="#comprobante">' . "\n" .
                '<ds:Transforms>' . "\n" .
                '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature">' .
                '</ds:Transform>' . "\n" .
                '</ds:Transforms>' . "\n" .
                '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">' .
                '</ds:DigestMethod>' . "\n" .
                '<ds:DigestValue>' . $documentDigest . '</ds:DigestValue>' . "\n" .
                '</ds:Reference>' . "\n" .
                '</ds:SignedInfo>';

            $signaturePayload = str_replace('<ds:SignedInfo', '<ds:SignedInfo ' . $xmlns, $sInfo);

            $resp = $this->sign($signaturePayload, $signatureResult);

            if ($resp != null) return $resp;


            if ($signatureResult != null) {
                $sig = '<ds:Signature ' . $xmlns . ' Id="Signature' . $this->signatureID . '">' . "\n" .
                    $sInfo . "\n" .
                    '<ds:SignatureValue Id="SignatureValue' . $this->signatureValueID . '">' . "\n" .
                    $signatureResult . "\n" .
                    '</ds:SignatureValue>' . "\n" .
                    $kInfo . "\n" .
                    '<ds:Object Id="Signature' . $this->signatureID . '-Object' . $this->signatureObjectID . '">' .
                    '<etsi:QualifyingProperties Target="#Signature' . $this->signatureID . '">' .
                    $prop .
                    '</etsi:QualifyingProperties>' .
                    '</ds:Object>' .
                    '</ds:Signature>';

                if ($this->tipoComprobante === '01')
                    $xml = str_replace('</factura>', $sig . '</factura>', $xml);
                elseif ($this->tipoComprobante === '07')
                    $xml = str_replace('</comprobanteRetencion>', $sig . '</comprobanteRetencion>', $xml);
                elseif ($this->tipoComprobante === '06')
                    $xml = str_replace('</guiaRemision>', $sig . '</guiaRemision>', $xml);
                elseif ($this->tipoComprobante === '04')
                    $xml = str_replace('</notaCredito>', $sig . '</notaCredito>', $xml);

                $xmlSigned = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . $xml;

                // guardar documento firmado
                try {
                    $respuesta = $xmlSigned;
                    
                    echo $xml;
                } catch (Exception $ex) {
                    $respuesta = array('error' => true, 'mensaje' => 'el documento fue firmado exitosamente pero no pudo ser guardado, ' . $ex->getMessage());
                }
            } else
                $respuesta = array('error' => true, 'mensaje' => 'error desconocido en la firma del documento consulte con el administrador');

        } catch (Exception $ex) {

            $respuesta = array('error' => true, 'mensaje' => $ex->getMessage());
            
        }

        return $respuesta;
    }


    public function getcertDigest()
    {
        $certDigest = openssl_x509_fingerprint($this->certificate, "sha1", true);
        $certDigest = base64_encode($certDigest);
        return $certDigest;
    }

    public function getIssuer()
    {
        $reversed = array_reverse($this->certData['issuer']);
        $certIssuer = array();
        foreach ($reversed as $item => $value) {
            $certIssuer[] = $item . '=' . $value;
        }
        return $certIssuer = implode(',', $certIssuer);

    }

    public function getSerial()
    {
        return $this->certData['serialNumber'];
    }

    public function getModulus()
    {
        $details = openssl_pkey_get_details($this->privateKey);
        $modulus = wordwrap(base64_encode($details['rsa']['n']), $this->config['wordwrap'], "\n", true);
        return $modulus;
    }

    public function getExponent()
    {
        $details = openssl_pkey_get_details($this->privateKey);
        $exponent = wordwrap(base64_encode($details['rsa']['e']), $this->config['wordwrap'], "\n", true);
        return $exponent;
    }

    public function sign($dataTosign, &$firmado = null)
    {
        $respuesta = null;
        try {

            openssl_sign($dataTosign, $signature, $this->privateKey);

            openssl_free_key($this->privateKey);

            if (openssl_verify($dataTosign, $signature, $this->public_key) != 1)
                $respuesta = array('error' => true, 'mensaje' => 'error al validar el documento firmado, firma alterada o mal estructurada');
            else
                $firmado = wordwrap(base64_encode($signature), $this->config['wordwrap'], "\n", true);

            openssl_free_key($this->public_key);

        } catch (Exception $ex) {
            $respuesta = array('error' => true, 'mensaje' => $ex->getMessage());
        }

        return $respuesta;

    }
}
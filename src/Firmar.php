<?php
/**
 * Created by PhpStorm.
 * User: svycar
 * Date: 26/3/18
 * Time: 16:37
 */

namespace Josefranciscocruzcorro\Firmador;

use DOMDocument;
use Exception;

class Firmar
{
    private $config;
    private $privateKey = null;
    private $publicKey = null;
    private $signTime = null;
    private $certData = null;
    private $claveAcceso = null;
    private $tipoComprobante = null;
    private $certificate = null;

    private $signatureID;
    private $signedInfoID;
    private $signedPropertiesID;
    private $signatureValueID;
    private $certificateID;
    private $referenceID;
    private $signatureSignedPropertiesID;
    private $signatureObjectID;

    /**
     * Firma constructor.
     */
    public function __construct($config = array(), $claveAcceso)
    {
        $this->claveAcceso = $claveAcceso;

        $this->tipoComprobante = substr($this->claveAcceso, 8, 2);

        $this->config = array_merge(array(
            'file' => null,
            'pass' => null,
            'wordwrap' => 64,
        ), $config);

    }

    public function verificarCertPKey()
    {

        try {
            $pathFirma = $this->config['file'];

            if (openssl_pkcs12_read(file_get_contents($pathFirma, FILE_USE_INCLUDE_PATH), $certs, $this->config['pass'])) {
                
                $x509cert = openssl_x509_read($certs['cert']);
                $certf = openssl_x509_parse($x509cert);
                $subject = $certf['subject']['CN'];
                $aux = null;
                
                if (array_key_exists('O', $certf['subject'])){
                   
                    $certificante = $certf['subject']['O'];

                    if ($certificante === "BANCO CENTRAL DEL ECUADOR") {

                        $aux = $certs['extracerts'];
                        foreach ($aux as $item) {
                            $x509cert = openssl_x509_read($item);
                            $certData = openssl_x509_parse($x509cert);
                            
                            //if (trim($subject) === trim($certData['subject']['CN'])) { OJO quite esta condicion
                                $this->certificate = $x509cert;
                                $this->certData = $certData;
                                break;
                            //}
                        }
                    } else if ($certificante === "SECURITY DATA S.A.") {
                            $this->certificate = $x509cert;
                            $this->certData = $certf;
                    } else if ($certificante === "SECURITY DATA S.A. 1") {
                            $this->certificate = $x509cert;
                            $this->certData = $certf;
                    } else if ($certificante === "SECURITY DATA S.A. 2") {
                            $this->certificate = $x509cert;
                            $this->certData = $certf;
                    }else {
                        $this->certificate = $x509cert;
                        $this->certData = $certf;
                    }
                } else {
                        $this->certificate = $x509cert;
                        $this->certData = $certf;
                } 

                if ($this->certificate === null || $this->certificate === false)
                    return array('error' => true, 'mensaje' => "No existe certificado valido: ".$certificante);

            } else
                return array('error' => true, 'mensaje' => "no se puede leer contenido del archivo p12");


            $this->publicKey = openssl_get_publickey($this->certificate);
            
            

            if ($this->publicKey === null || $this->publicKey === false)
                return array('error' => true, 'mensaje' => "no se pudo acceder a la clave publica del certificado");

            if ($this->getPublicPem() === "") {
                return array('error' => true, 'mensaje' => "No existe ningún certificado para firmar.");

            }

            $resp = $this->getPrivateKey();

            if ($resp["error"] === true)
                return array('error' => true, 'mensaje' => $resp["mensaje"]);


            $fecha_actual = strtotime(date("Y-m-d H:i:s", time()));
            $fecha_entrada = strtotime(date("Y-m-d H:i:s", $this->certData['validTo_time_t']));

            if ($fecha_actual > $fecha_entrada)
                return array('error' => true, 'mensaje' => "El certificado con el que intenta firmar el comprobante esta expirado\nfavor actualize su certificado digital con la Autoridad Certificadora");

            if ($aux != null){ /* Aqui chequeo si tiene valor aux */
                if ($this->getRucCert($aux) === false)
                    return array('error' => true, 'mensaje' => $aux);

                $rucCmp = substr($this->claveAcceso, 10, 13);

                if ($rucCmp != $aux)
                    return array('error' => true, 'mensaje' => 'ruc del certificado no es igual al ruc del emisor');
            }    

            $this->generarId();


        } catch (Exception $ex) {
            return array('error' => true, 'mensaje' => $ex->getMessage());
        }
        return array('error' => false, 'mensaje' => "");
    }

    public function getPublicPem()
    {
        $publicPEM = "";
        openssl_x509_export($this->certificate, $publicPEM);
        $publicPEM = str_replace("-----BEGIN CERTIFICATE-----", "", $publicPEM);
        $publicPEM = str_replace("-----END CERTIFICATE-----", "", $publicPEM);
        $publicPEM = str_replace("\n", "", $publicPEM);
        $publicPEM = wordwrap($publicPEM, $this->config['wordwrap'], "\n", true);
        return $publicPEM;
    }

    private function getPrivateKey()
    {
        try {
            $pfx =  $this->config['file'];
            $password = $this->config['pass'];
            $nombreKey = "firma_temp.pem";

            if (file_exists($nombreKey))
                unlink($nombreKey);
            $aux = 'openssl pkcs12 -in ' . $pfx . ' -nocerts -out ' . $nombreKey . ' -passin pass:' . $password . ' -passout pass:' . $password . ' 2>&1';
            $salida = shell_exec('openssl pkcs12 -in ' . $pfx . ' -nocerts -out ' . $nombreKey . ' -passin pass:' . $password . ' -passout pass:' . $password . ' 2>&1');
                
            //if (strpos($salida, 'verified OK') !== false) {

                $pemChain = file_get_contents($nombreKey);

                preg_match_all('/(-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----)/si', $pemChain, $matches);

                foreach ($matches[0] as $i => $items) {

                    $pkey = openssl_pkey_get_private($items, $this->config['pass']);

                    $this->privateKey = openssl_get_privatekey($pkey);

                    //$estado = openssl_x509_check_private_key($this->certificate, $this->privateKey);

                    if (openssl_x509_check_private_key($this->certificate, $this->privateKey)) {
                        break;
                    }
                    openssl_free_key($this->privateKey);
                }

                unlink($nombreKey);

                if ($this->privateKey === null)
                    return array('error' => true, 'mensaje' => "No se pudo acceder a la clave privada del certificado");

                if (openssl_x509_check_private_key($this->certificate, $this->privateKey) === false) {
                    return array('error' => true, 'mensaje' => "la clave privara no corresponde al certificado.");
                }

            /*} else
                return array('error' => true, 'mensaje' => $salida);*/

        } catch (Exception $ex) {
            return array('error' => true, 'mensaje' => $ex->getMessage());
        }

        return array('error' => false, 'mensaje' => "");
    }

    public function getRucCert(&$output)
    {
        foreach ($this->certData['extensions'] as $clave => $value) {
            $output = "";
            if (strpos($clave, "3.11") !== false) {
                $aux = explode("\r", $value);
                if (sizeof($aux) === 2) {
                    $output = $aux[1];
                    return true;
                } else {
                    $output = 'error al dividir la propiedad del certificado 3.11';
                    return false;
                }
            }
        }
        $output = 'certificado no posee un ruc registrado para facturacion electronica, favor actualize su certificado digital con la Autoridad Certificadora';
        return false;
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

    public function getValidoHasta()
    {
        return date('Y-m-d H:i:s', $this->certData['validTo_time_t']);
    }

    public function firmar($xml)
    {
        $respuesta = null;

        try {
            if (empty($this->publicKey) || empty($this->privateKey)) return $xml;
            $payload = $xml;
            $xml = new DOMDocument();
            $xml->loadXML($payload);
            $xml->formatOutput = false;
            $xml->preserveWhiteSpace = false;

            $xml = $xml->saveXML($xml->documentElement);

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

            $publicPEM = $this->getPublicPem();

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
                    //file_put_contents($docFirmados . DIRECTORY_SEPARATOR . $this->claveAcceso . '.xml', $xmlSigned);
                    echo $xmlSigned;
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

            if (openssl_verify($dataTosign, $signature, $this->publicKey) != 1)
                $respuesta = array('error' => true, 'mensaje' => 'error al validar el documento firmado, firma alterada o mal estructurada');
            else
                $firmado = wordwrap(base64_encode($signature), $this->config['wordwrap'], "\n", true);

            openssl_free_key($this->publicKey);

        } catch (Exception $ex) {
            $respuesta = array('error' => true, 'mensaje' => $ex->getMessage());
        }

        return $respuesta;

    }

}
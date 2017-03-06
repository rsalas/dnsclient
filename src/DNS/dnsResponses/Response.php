<?php
namespace DNS\dnsResponses;

class Response
{
    protected $responsecounter;
    protected $resourceResults;
    protected $nameserverResults;
    protected $additionalResults;
    protected $resourceResponses;
    protected $nameserverResponses;
    protected $additionalResponses;
    protected $queries;
    private $questions;
    private $answers;
    private $authorative;
    private $truncated;
    private $recursionRequested;
    private $recursionAvailable;
    private $authenticated;
    private $dnssecAware;

    const RESULTTYPE_RESOURCE = 'resource';
    const RESULTTYPE_NAMESERVER = 'nameserver';
    const RESULTTYPE_ADDITIONAL = 'additional';

    public function __construct()
    {
        $this->authorative = false;
        $this->truncated = false;
        $this->recursionRequested = false;
        $this->recursionAvailable = false;
        $this->authenticated = false;
        $this->dnssecAware = false;
        $this->responsecounter = 12;
        $this->queries = array();
        $this->resourceResults = array();
        $this->nameserverResults = array();
        $this->additionalResults = array();
    }

    public function addResult($result, $recordtype)
    {
        switch ($recordtype) {
            case Response::RESULTTYPE_RESOURCE:
                $this->resourceResults[] = $result;
                break;
            case Response::RESULTTYPE_NAMESERVER:
                $this->nameserverResults[] = $result;
                break;
            case Response::RESULTTYPE_ADDITIONAL:
                $this->additionalResults[] = $result;
                break;
            default:
                // $this->responsecounter = 12;
                break;
        }
        /*
         * Reset response counter to start at beginning of response
         */
    }

    public function addQuery($query)
    {
        $this->queries[] = $query;
    }

    public function getQueries()
    {
        return $this->queries;
    }

    public function setAnswerCount($count)
    {
        $this->answers = $count;
    }

    public function getAnswerCount()
    {
        return $this->answers;
    }

    public function setQueryCount($count)
    {
        $this->questions = $count;
    }

    public function getQueryCount()
    {
        return $this->questions;
    }

    public function setAuthorative($flag)
    {
        $this->authorative = $flag;
    }

    public function getAuthorative()
    {
        return $this->authorative;
    }

    public function setTruncated($flag)
    {
        $this->truncated = $flag;
    }

    public function getTruncated()
    {
        return $this->truncated;
    }

    public function setRecursionRequested($flag)
    {
        $this->recursionRequested = $flag;
    }

    public function getRecursionRequested()
    {
        return $this->recursionRequested;
    }

    public function setRecursionAvailable($flag)
    {
        $this->recursionAvailable = $flag;
    }

    public function getRecursionAvailable()
    {
        return $this->recursionAvailable;
    }

    public function setAuthenticated($flag)
    {
        $this->authenticated = $flag;
    }

    public function getAuthenticated()
    {
        return $this->authenticated;
    }

    public function setDnssecAware($flag)
    {
        $this->dnssecAware = $flag;
    }

    public function getDnssecAware()
    {
        return $this->dnssecAware;
    }

    public function getResourceResults()
    {
        return $this->resourceResults;
    }

    public function getNameserverResults()
    {
        return $this->nameserverResults;
    }

    public function getAdditionalResults()
    {
        return $this->additionalResults;
    }

    public function readResponse($buffer, $count = 1, $offset = "")
    {
        if ($offset == "") { // no offset so use and increment the ongoing counter
            $return = substr($buffer, $this->responsecounter, $count);
            $this->responsecounter += $count;
        } else {
            $return = substr($buffer, $offset, $count);
        }
        return $return;
    }

    public function readRecord($buffer, $resulttype = '')
    {
        $domain = $this->readDomainLabel($buffer);
        $ans_header_bin = $this->readResponse($buffer, 10); // 10 byte header
        $ans_header = unpack("ntype/nclass/Nttl/nlength", $ans_header_bin);
        // echo "Record Type ".$ans_header['type']." Class ".$ans_header['class']." TTL ".$ans_header['ttl']." Length ".$ans_header['length']."\n";
        // $this->DebugBinary($buffer);
        $types = new \DNS\dnsData\Types();
        $typeid = $types->GetById($ans_header['type']);
        // $extras = array();
        switch ($typeid) {
            case 'A':
                $result = new \DNS\dnsData\Aresult(implode(".", unpack("Ca/Cb/Cc/Cd", $this->readResponse($buffer, 4))));
                break;

            case 'NS':
                $result = new \DNS\dnsData\NSresult($this->readDomainLabel($buffer));
                break;

            case 'PTR':
                $result = new \DNS\dnsData\PTRresult($this->readDomainLabel($buffer));
                break;

            case 'CNAME':
                $result = new \DNS\dnsData\CNAMEresult($this->readDomainLabel($buffer));
                break;

            case 'MX':
                $result = new \DNS\dnsData\MXresult();
                $prefs = $this->readResponse($buffer, 2);
                $prefs = unpack("nprio", $prefs);
                $result->setPrio($prefs['prio']);
                $result->setServer($this->readDomainLabel($buffer));
                break;

            case 'SOA':
                $result = new \DNS\dnsData\SOAresult();
                $result->setNameserver($this->readDomainLabel($buffer));
                $result->setResponsible($this->readDomainLabel($buffer));
                $buffer = $this->readResponse($buffer, 20);
                $extras = unpack("Nserial/Nrefresh/Nretry/Nexpiry/Nminttl", $buffer);
                $result->setSerial($extras['serial']);
                $result->setRefresh($extras['refresh']);
                $result->setRetry($extras['retry']);
                $result->setExpiry($extras['expiry']);
                $result->setMinttl($extras['minttl']);
                break;

            case 'TXT':
                $result = new \DNS\dnsData\TXTresult($this->readResponse($buffer, $ans_header['length']));
                break;

            case 'DS':
                $stuff = $this->readResponse($buffer, $ans_header['length']);
                $length = (($ans_header['length'] - 4) * 2) - 8;
                $stuff = unpack("nkeytag/Calgo/Cdigest/H" . $length . "string/H*rest", $stuff);
                $stuff['string'] = strtoupper($stuff['string']);
                $stuff['rest'] = strtoupper($stuff['rest']);
                $result = new \DNS\dnsData\DSresult($stuff['keytag'], $stuff['algo'], $stuff['digest'], $stuff['string'], $stuff['rest']);
                break;

            case 'DNSKEY':
                $stuff = $this->readResponse($buffer, $ans_header['length']);
                $this->keytag($stuff, $ans_header['length']);
                $this->keytag2($stuff, $ans_header['length']);
                $extras = unpack("nflags/Cprotocol/Calgorithm/a*pubkey", $stuff);
                $flags = sprintf("%016b\n", $extras['flags']);
                $result = new \DNS\dnsData\DNSKEYresult($extras['flags'], $extras['protocol'], $extras['algorithm'], $extras['pubkey']);
                $result->setKeytag($this->keytag($stuff, $ans_header['length']));
                if ($flags{7} == '1') {
                    $result->setZoneKey(true);
                }
                if ($flags{15} == '1') {
                    $result->setSep(true);
                }
                break;

            case 'RRSIG':
                $stuff = $this->readResponse($buffer, 18);
                //$length = $ans_header['length'] - 18;
                $test = unpack("ntype/calgorithm/clabels/Noriginalttl/Nexpiration/Ninception/nkeytag", $stuff);
                $result = new \DNS\dnsData\RRSIGresult($test['type'], $test['algorithm'], $test['labels'], $test['originalttl'], $test['expiration'], $test['inception'], $test['keytag']);
                $name = $this->readDomainLabel($buffer);
                $result->setSignername($name);
                $sig = $this->readResponse($buffer, $ans_header['length'] - (strlen($name) + 2) - 18);
                $result->setSignature($sig);
                $result->setSignatureBase64(base64_encode($sig));
                break;

            default: // something we can't deal with
                $result = new \DNS\dnsData\Result();
                #echo "Length: ".$ans_header['length']."\n";
                $stuff = $this->readResponse($buffer, $ans_header['length']);
                $result->setData($stuff);
                break;

        }
        $result->setDomain($domain);
        $result->setType($ans_header['type']);
        $result->setTypeid($typeid);
        $result->setClass($ans_header['class']);
        $result->setTtl($ans_header['ttl']);
        $this->AddResult($result, $resulttype);
        return;
    }


    private function keytag($key, $keysize)
    {
        $ac = 0;
        for ($i = 0; $i < $keysize; $i++) {
            $keyp = unpack("C", $key[$i]);
            $ac += (($i & 1) ? $keyp[1] : $keyp[1] << 8);
        }
        $ac += ($ac >> 16) & 0xFFFF;
        $keytag = $ac & 0xFFFF;
        return $keytag;
    }

    private function keytag2($key, $keysize)
    {
        $ac = 0;
        for ($i = 0; $i < $keysize; $i++) {
            $keyp = unpack("C", $key[$i]);
            $ac += ($i % 2 ? $keyp[1] : 256 * $keyp[1]);
        }
        $ac += ($ac / 65536) % 65536;
        $keytag = $ac % 65536;
        return $keytag;
    }

    private function readDomainLabel($buffer)
    {
        $count = 0;
        $labels = $this->readDomainLabels($buffer, $this->responsecounter, $count);
        $domain = implode(".", $labels);
        $this->responsecounter += $count;
        #$this->writeLog("Label ".$domain." len ".$count);
        return $domain;
    }

    private function readDomainLabels($buffer, $offset, &$counter = 0)
    {
        $labels = array();
        $startoffset = $offset;
        $return = false;
        while (!$return) {
            $label_len = ord($this->readResponse($buffer, 1, $offset++));
            if ($label_len <= 0) {
                $return = true;
            } // end of data
            elseif ($label_len < 64) { // uncompressed data
                $labels[] = $this->readResponse($buffer, $label_len, $offset);
                $offset += $label_len;
            } else { // label_len>=64 -- pointer
                $nextitem = $this->readResponse($buffer, 1, $offset++);
                $pointer_offset = (($label_len & 0x3f) << 8) + ord($nextitem);
                // Branch Back Upon Ourselves...
                // $this->writeLog("Label Offset: ".$pointer_offset);

                $pointer_labels = $this->readDomainLabels($buffer, $pointer_offset);
                foreach ($pointer_labels as $ptr_label) {
                    $labels[] = $ptr_label;
                }
                $return = true;
            }
        }
        $counter = $offset - $startoffset;
        return $labels;
    }

    public function setResourceResultCount($count)
    {
        $this->resourceResponses = $count;
    }

    public function getResourceResultCount()
    {
        return $this->resourceResponses;
    }

    public function setNameserverResultCount($count)
    {
        $this->nameserverResponses = $count;
    }

    public function getNameserverResultCount()
    {
        return $this->nameserverResponses;
    }

    public function setAdditionalResultCount($count)
    {
        $this->additionalResponses = $count;
    }

    public function getAdditionalResultCount()
    {
        return $this->additionalResponses;
    }
/*
    private function DebugBinary($data)
    {
        echo pack("S", $data);
        for ($a = 0; $a < strlen($data); $a++) {
            echo $a;
            echo "\t";
            printf("%d", $data[$a]);
            echo "\t";
            $hex = bin2hex($data[$a]);
            echo "0x" . $hex;
            echo "\t";
            $dec = hexdec($hex);
            echo $dec;
            echo "\t";
            if (($dec > 30) && ($dec < 150)) echo $data[$a];
            echo "\n";
        }
    }*/
}

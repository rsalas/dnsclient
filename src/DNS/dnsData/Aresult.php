<?php
namespace DNS\dnsData;

class Aresult extends Result
{
    private $ipv4;

    public function __construct($ip)
    {
        parent::__construct();
        $this->setIpv4($ip);
    }

    public function setIpv4($ip)
    {
        $this->ipv4 = $ip;
    }

    public function getIpv4()
    {
        return $this->ipv4;
    }
}

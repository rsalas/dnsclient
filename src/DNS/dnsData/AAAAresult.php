<?php
namespace DNS\dnsData;

class AAAAresult extends Result
{
    private $ipv6;

    public function __construct($ip)
    {
        parent::__construct();
        $this->setIpv6($ip);
    }

    public function setIpv6($ip)
    {
        $this->ipv6 = $ip;
    }

    public function getIpv6()
    {
        return $this->ipv6;
    }
}

<?php
namespace DNS\dnsData;

class Aresult extends Result
{
    private $_ipv4;

    public function __construct($ip)
    {
        parent::__construct();
        $this->setIpv4($ip);
    }

    public function setIpv4($ip)
    {
        $this->_ipv4 = $ip;
    }

    public function getIpv4()
    {
        return $this->_ipv4;
    }
}

<?php
namespace DNS\dnsData;

// Reference https://www.internic.net/domain/root.zone
class Nameserver
{
    private $ns;
    public function __construct()
    {
        include "rootNameServers.php";
        $this->ns = $ns;
    }

    public function getNs($tld)
    {
        return $this->ns[$tld];
    }
}

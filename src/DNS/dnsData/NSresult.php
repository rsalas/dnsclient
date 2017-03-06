<?php
namespace DNS\dnsData;

class NSresult extends Result
{
    private $nameserver;

    public function __construct($ns)
    {
        parent::__construct();
        $this->setNameserver($ns);
    }

    public function setNameserver($server)
    {
        $this->nameserver = $server;
    }

    public function getNameserver()
    {
        return $this->nameserver;
    }
}

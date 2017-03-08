<?php
namespace DNS\dnsData;

class SRVresult extends Result
{
    private $priority;
    private $weight;
    private $port;
    private $data;

    public function setPriority($prio)
    {
        $this->priority = $prio;
    }

    public function getPriority()
    {
        return $this->priority;
    }

    public function setWeight($weight)
    {
        $this->weight = $weight;
    }

    public function getWeight()
    {
        return $this->weight;
    }

    public function setPort($port)
    {
        $this->port = $port;
    }

    public function getPort()
    {
        return $this->port;
    }

    public function setData($data)
    {
        $this->data = $data;
    }

    public function getData()
    {
        return $this->data;
    }
}

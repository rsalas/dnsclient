<?php
namespace DNS\dnsData;

class PTRresult extends Result
{
    private $data;

    public function __construct($data)
    {
        parent::__construct();
        $this->setData($data);
    }

    public function setData($data)
    {
        $this->dat = $data;
    }

    public function getData()
    {
        return $this->data;
    }
}

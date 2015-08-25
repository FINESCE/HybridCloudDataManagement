<?php

class ApiController extends Controller {
    private $host = "localhost:9443";
    private $authenticationRules = [
        'username'  => 'required',
        'password'  => 'required',
        'host'      => ''
    ];

    private $listRules = [
        'token'     => 'required',
        'auth'      => 'required',
        'host'      => '',
        'container' => ''
    ];

    private $createRules = [
        'token'     => 'required',
        'auth'      => 'required',
        'host'      => '',
        'container' => 'required'
    ];

    private $deleteRules = [
        'token'     => 'required',
        'auth'      => 'required',
        'host'      => '',
        'container' => 'required',
        'object'    => ''
    ];

    private $uploadRules = [
        'token'     => 'required',
        'auth'      => 'required',
        'container' => 'required',
        'host'      => '',
        'object'    => 'required',
        'file'      => ''
    ];

    private $downloadRules = [
        'token'     => 'required',
        'auth'      => 'required',
        'container' => 'required',
        'host'      => '',
        'object'    => 'required',
    ];

    protected $client;
    public function __construct()
    {
        $this->client = new  GuzzleHttp\Client();
        $this->host = gethostname().":9443";
    }
    public function authenticate()
    {
        $validator = Validator::make(Input::all(), $this->authenticationRules);
        if ($validator->fails()) {
            return  Response::make('Bad Request', 400);
        } else {
            $host = $this->host;
            if (!is_null(Input::get('host'))) $host = Input::get('host');
            //Process the authentication here
            try {
                $res = $this->client->get('https://'.$host.'/auth/v1.0/', [
                    'headers'         => array(
                        'X-Auth-User'   => Input::get('username'),
                        'X-Auth-Key'    => Input::get('password')
                    ),
                    'verify' => false
                ]);
                $response = array();
                $response['token'] = $res->getHeaders()['X-Auth-Token'][0];
                $response['auth_url'] = $res->getHeaders()['X-Storage-Url'][0];
                $response['auth'] = explode('/',$response['auth_url'])[4];
                return json_encode($response);
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make($e->getResponse(), $e->getCode());
            } catch(Exception $e) {
                return  Response::make('Internal Server Error', 500);
            }


        }
    }

    public function listData() {
        $validator = Validator::make(Input::all(), $this->listRules);
        if ($validator->fails()) {
            return  Response::make('Bad Request', 400);
        } else {
            try {
                $host = $this->host;
                if (!is_null(Input::get('host'))) $host = Input::get('host');

                $container = Input::get('container');
                if (!isset($container)) $container = '';
                $res = $this->client->get('https://'.$host.'/cdmi/'.Input::get('auth').'/'.$container, [
                    'headers' => [
                        'X-Auth-Token'                  => Input::get('token'),
                        'Content-Type'                  => 'application/cdmi-container',
                        'X-CDMI-Specification-Version'  => '1.0.1',
                        'Accept'                        => '*/*'
                    ],
                    'verify' => false,
                    'timeout' => 5
                ]);
                $response = array();
                $response['token'] = $res->getBody();
                $res_array['items'] = json_decode($res->getBody()->getContents())->children;
                return json_encode($res_array);
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make($e->getResponse(), $e->getCode());
            } catch(Exception $e) {
                return  Response::make('Internal Server Error', 500);
            }
        }
    }

    public function create() {
        $validator = Validator::make(Input::all(), $this->createRules);
        if ($validator->fails()) {
            return  Response::make('Bad Request', 400);
        } else {
            try {
                $host = $this->host;
                if (!is_null(Input::get('host'))) $host = Input::get('host');

                $container = Input::get('container');
                if (!isset($container)) $container = '';
                $res = $this->client->put('https://'.$host.'/cdmi/'.Input::get('auth').'/'.$container, [
                    'headers' => [
                        'X-Auth-Token'                  => Input::get('token'),
                        'Content-Type'                  => 'application/cdmi-container',
                        'X-CDMI-Specification-Version'  => '1.0.1',
                        'Accept'                        => 'application/cdmi-container'
                    ],
                    'body'      => '{"metadata": {}}',
                    'verify'    => false,
                    'timeout'   => 5
                ]);
                if ($res->getBody()->getContents() != '') return Response::make(json_encode(array('status' => 'OK')), 201);
                return Response::make(json_encode(array('status' => 'KO')), 409); //Return a created
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make($e->getResponse(), $e->getCode());
            } catch(Exception $e) {
                return  Response::make('Internal Server Error', 500);
            }
        }
    }

    public function delete() {
        $validator = Validator::make(Input::all(), $this->deleteRules);
        if ($validator->fails()) {
            return  Response::make('Bad Request', 400);
        } else {
            try {
                $host = $this->host;
                if (!is_null(Input::get('host'))) $host = Input::get('host');

                $container = Input::get('container');
                if (!isset($container)) $container = '';

                $object = '';
                if (!is_null(Input::get('object'))) $object = '/'.Input::get('object');
                $res = $this->client->delete('https://'.$host.'/cdmi/'.Input::get('auth').'/'.$container.$object, [
                    'headers' => [
                        'X-Auth-Token'                  => Input::get('token'),
                        'Content-Type'                  => 'application/cdmi-object',
                        'X-CDMI-Specification-Version'  => '1.0.1',
                    ],
                    'verify' => false,
                    'timeout' => 5
                ]);

                return Response::make(json_encode(array('status' => 'OK')));
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make(json_encode(array('status' => 'KO')), 404);
            } catch(Exception $e) {
                return Response::make(json_encode(array('status' => 'KO')), 404);

            }
        }
    }

    public function upload() {
        $validator = Validator::make(Input::all(), $this->uploadRules);
        if ($validator->fails()) {
		//dd(Input::all());
            return  Response::make(Input::get('container'), 400);
        } else {
            try {
                $host = $this->host;
                if (!is_null(Input::get('host'))) $host = Input::get('host');
                $request = Request::instance();
                $content = $request->getContent();
                $putData = tmpfile();          //<== the magic solution !
                fwrite($putData, $content);
                fseek($putData, 0);
                $uri = stream_get_meta_data($putData)['uri'];
                $container = Input::get('container');

                $url = 'https://'.$host.'/cdmi/'.Input::get('auth').'/'.$container.'/'.Input::get('object');
                if (Input::get('key') == null) $command = "curl -k  -X PUT -H 'X-Auth-Token: ".Input::get('token')."' -H 'Content-Type: application/stream-octet' -H 'Accept: */*' --data-binary '@".$uri."' " . $url;
                else  $command = "curl -k -f  -X PUT -H 'X-Auth-Token: ".Input::get('token')."' -H 'Content-Type: application/stream-octet' -H 'X-AES-Key: ".Input::get('key')."' -H 'Accept: */*' --data-binary '@".$uri."' " . $url;

                passthru($command, $status);
                fclose($putData);
                if ($status == 0) return Response::make(json_encode(['status' => 'created']));
                return Response::make(json_encode(['status' => 'KO']),304);
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make($e->getResponse(),$e->getCode());
            } catch(Exception $e) {
                return  Response::make('Internal Server Error', 500);
            }
        }
    }

    public function download()
    {
        $validator = Validator::make(Input::all(), $this->downloadRules);
        if ($validator->fails()) {
            return  Response::make('Bad Request', 400);
        } else {
            try {
                $host = $this->host;
                if (!is_null(Input::get('host'))) $host = Input::get('host');

                $container = Input::get('container');

                $url = 'https://'.$host.'/cdmi/'.Input::get('auth').'/'.$container.'/'.Input::get('object');
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-Auth-Token: '. Input::get('token')]);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/stream-octet']);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: */*']);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-CDMI-Specification-Version: 1.0.1']);
                if (Input::get('key') != null) curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-AES-Key: '.Input::get('key')]);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $resp = curl_exec($ch);
                //curl_close($ch);
                if (Input::get('key') != null) {
                    $response =  Response::make($resp, 200);
                    $response->header('Content-Type', 'application/octet-stream');
                    $response->header('Content-Disposition',' attachment; filename="'.Input::get('object').'"');
                    return $response;
                } else {
                    $resp = json_decode($resp);
                    $data = base64_decode($resp->value);
                    $mimetype = $resp->mimetype;
                    $objectname = $resp->objectName;
                    $response =  Response::make($data, 200);
                    $response->header('Content-Type', $mimetype);
                    //$response->header('Content-Length', strlen($response));
                    $response->header('Content-Disposition',' attachment; filename="'.$objectname.'"');
                    return $response;
                }
            } catch(\GuzzleHttp\Exception\RequestException $e) {
                if ($e->getCode() == 0) return Response::make('Gateway Timeout', 504);
                return Response::make($e->getResponse(),$e->getCode());
            } catch(Exception $e) {
                return  Response::make('Internal Server Error', 500);
            }
        }
    }
}

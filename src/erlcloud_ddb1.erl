%% -*- mode: erlang;erlang-indent-level: 4;indent-tabs-mode: nil -*-

%% @author Ransom Richardson <ransom@ransomr.net>
%% @doc
%% An low level Erlang interface to Amazon's DynamoDB.
%%
%% This API is lower level than the one in `erlcloud_ddb'. It takes JSON terms as
%% defined by `jsx'.
%%
%% @end

-module(erlcloud_ddb1).

-include_lib("erlcloud/include/erlcloud.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

%% DDB API Functions
-export([batch_get_item/1, batch_get_item/2,
         batch_write_item/1, batch_write_item/2,
         create_table/4, create_table/5,
         delete_item/2, delete_item/3, delete_item/4,
         delete_table/1, delete_table/2,
         describe_table/1, describe_table/2,
         get_item/2, get_item/3, get_item/4,
         list_tables/0, list_tables/1, list_tables/2,
         put_item/2, put_item/3, put_item/4,
         %% Note that query is a Erlang reserved word, so we use q instead
         q/2, q/3, q/4,
         scan/1, scan/2, scan/3,
         update_item/3, update_item/4, update_item/5,
         update_table/3, update_table/4
        ]).

%% Helpers
-export([key_value/1, backoff/1, retry/2]).

-export_type([key/0, key_schema_value/0, key_schema/0, json_return/0,
              batch_write_item_request/0, attempt/0, retry_fun/0]).

-type table_name() :: binary().
-type attr_type() :: binary().
-type attr_value() :: binary().
-type attr() :: {attr_type(), attr_value()}.
-type hash_key() :: attr().
-type range_key() :: attr().
-type hash_range_key() :: {hash_key(), range_key()}.
-type key() :: hash_key() | hash_range_key().
-type attr_name() :: binary().
-type key_schema_value() :: {attr_name(), attr_type()}.
-type key_schema() :: key_schema_value() | {key_schema_value(), key_schema_value()}.
-type item() :: jsx:json_term().
-type opts() :: jsx:json_term().
-type updates() :: jsx:json_term().
-type json_return() :: {ok, jsx:json_term()} | {error, term()}.

-spec key_value(key()) -> jsx:json_term().
key_value({{HK, HV} = HashKey, {RK, RV} = RangeKey}) when
      is_binary(HK), is_binary(HV), is_binary(RK), is_binary(RV) ->
    [{<<"HashKeyElement">>, [HashKey]}, {<<"RangeKeyElement">>, [RangeKey]}];
key_value({HK, HV} = HashKey) when
      is_binary(HK), is_binary(HV) ->      
    [{<<"HashKeyElement">>, [HashKey]}].
    
-spec key_json(key()) -> {binary(), jsx:json_term()}.
key_json(Key) ->
    {<<"Key">>, key_value(Key)}.

-spec hash_key_json(hash_key()) -> {binary(), jsx:json_term()}.
hash_key_json(HashKey) ->
    {<<"HashKeyValue">>, [HashKey]}.

-spec item_json(item()) -> {binary(), item()}.
item_json(Item) ->
    {<<"Item">>, Item}.

-spec updates_json(updates()) -> {binary(), updates()}.
updates_json(Updates) ->
    {<<"AttributeUpdates">>, Updates}.


-type batch_get_item_request_item() :: {table_name(), [key(),...], opts()} | {table_name(), [key(),...]}.

-spec batch_get_item_request_item_json(batch_get_item_request_item()) -> {binary(), jsx:json_term()}.
batch_get_item_request_item_json({Table, Keys}) ->
    batch_get_item_request_item_json({Table, Keys, []});
batch_get_item_request_item_json({Table, Keys, Opts}) ->
    {Table, [{<<"Keys">>, [key_value(K) || K <- Keys]}] ++ Opts}.

-spec batch_get_item([batch_get_item_request_item()]) -> json_return().
batch_get_item(RequestItems) ->
    batch_get_item(RequestItems, default_config()).

-spec batch_get_item([batch_get_item_request_item()], aws_config()) -> json_return().
batch_get_item(RequestItems, Config) ->
    Json = [{<<"RequestItems">>, [batch_get_item_request_item_json(R) || R <- RequestItems]}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.BatchGetItem", Json).

-type batch_write_item_put() :: {put, item()}.
-type batch_write_item_delete() :: {delete, key()}.
-type batch_write_item_request() :: batch_write_item_put() | batch_write_item_delete().
-type batch_write_item_request_item() :: {table_name(), [batch_write_item_request()]}.

-spec batch_write_item_request_json(batch_write_item_request()) -> {binary(), jsx:json_term()}.
batch_write_item_request_json({put, Item}) ->
    {<<"PutRequest">>, [item_json(Item)]};
batch_write_item_request_json({delete, Key}) ->
    {<<"DeleteRequest">>, [key_json(Key)]}.

-spec batch_write_item_request_item_json(batch_write_item_request_item()) -> {binary(), jsx:json_term()}.
batch_write_item_request_item_json({Table, Requests}) ->
    {Table, [[batch_write_item_request_json(R)] || R <- Requests]}.

-spec batch_write_item([batch_write_item_request_item()]) -> json_return().
batch_write_item(RequestItems) ->
    batch_get_item(RequestItems, default_config()).

-spec batch_write_item([batch_write_item_request_item()], aws_config()) -> json_return().
batch_write_item(RequestItems, Config) ->
    Json = [{<<"RequestItems">>, [batch_write_item_request_item_json(R) || R <- RequestItems]}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.BatchWriteItem", Json).


-spec key_schema_value_json(key_schema_value()) -> jsx:json_term().
key_schema_value_json({Name, Type}) ->
    [{<<"AttributeName">>, Name}, {<<"AttributeType">>, Type}].

-spec key_schema_json(key_schema()) -> {binary(), jsx:json_term()}.
key_schema_json({{_, _} = HashKey, {_, _} = RangeKey}) ->
    {<<"KeySchema">>, [{<<"HashKeyElement">>, key_schema_value_json(HashKey)},
                       {<<"RangeKeyElement">>, key_schema_value_json(RangeKey)}]};
key_schema_json(HashKey) ->
    {<<"KeySchema">>, [{<<"HashKeyElement">>, key_schema_value_json(HashKey)}]}.
                       
-spec create_table(table_name(), key_schema(), non_neg_integer(), non_neg_integer()) -> json_return().
create_table(Table, KeySchema, ReadUnits, WriteUnits) ->
    create_table(Table, KeySchema, ReadUnits, WriteUnits, default_config()).

-spec create_table(table_name(), key_schema(), non_neg_integer(), non_neg_integer(), aws_config()) -> json_return().
create_table(Table, KeySchema, ReadUnits, WriteUnits, Config) ->
    Json = [{<<"TableName">>, Table},
            key_schema_json(KeySchema),
            {<<"ProvisionedThroughput">>, [{<<"ReadCapacityUnits">>, ReadUnits},
                                           {<<"WriteCapacityUnits">>, WriteUnits}]}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.CreateTable", Json).

    
-spec delete_item(table_name(), key()) -> json_return().
delete_item(Table, Key) ->
    delete_item(Table, Key, [], default_config()).

-spec delete_item(table_name(), key(), opts()) -> json_return().
delete_item(Table, Key, Opts) ->
    delete_item(Table, Key, Opts, default_config()).

-spec delete_item(table_name(), key(), opts(), aws_config()) -> json_return().
delete_item(Table, Key, Opts, Config) ->
    Json = [{<<"TableName">>, Table},
            key_json(Key)] 
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.DeleteItem", Json).

    
-spec delete_table(table_name()) -> json_return().
delete_table(Table) ->
    delete_table(Table, default_config()).

-spec delete_table(table_name(), aws_config()) -> json_return().
delete_table(Table, Config) ->
    Json = [{<<"TableName">>, Table}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.DeleteTable", Json).

    
-spec describe_table(table_name()) -> json_return().
describe_table(Table) ->
    describe_table(Table, default_config()).

-spec describe_table(table_name(), aws_config()) -> json_return().
describe_table(Table, Config) ->
    Json = [{<<"TableName">>, Table}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.DescribeTable", Json).


-spec get_item(table_name(), key()) -> json_return().
get_item(Table, Key) ->
    get_item(Table, Key, [], default_config()).

-spec get_item(table_name(), key(), opts()) -> json_return().
get_item(Table, Key, Opts) ->
    get_item(Table, Key, Opts, default_config()).

-spec get_item(table_name(), key(), opts(), aws_config()) -> json_return().
get_item(Table, Key, Opts, Config) ->
    Json = [{<<"TableName">>, Table},
            key_json(Key)] 
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.GetItem", Json).


-spec list_tables() -> json_return().
list_tables() ->
    list_tables([], default_config()).

-spec list_tables(opts()) -> json_return().
list_tables(Opts) ->
    list_tables(Opts, default_config()).

-spec list_tables(opts(), aws_config()) -> json_return().
list_tables(Opts, Config) ->
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.ListTables", Opts).

    
-spec put_item(table_name(), item()) -> json_return().
put_item(Table, Item) ->
    put_item(Table, Item, [], default_config()).

-spec put_item(table_name(), item(), opts()) -> json_return().
put_item(Table, Item, Opts) ->
    put_item(Table, Item, Opts, default_config()).

-spec put_item(table_name(), item(), opts(), aws_config()) -> json_return().
put_item(Table, Item, Opts, Config) ->
    Json = [{<<"TableName">>, Table},
            item_json(Item)] 
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.PutItem", Json).


-spec q(table_name(), hash_key()) -> json_return().
q(Table, HashKey) ->
    q(Table, HashKey, [], default_config()).

-spec q(table_name(), hash_key(), opts()) -> json_return().
q(Table, HashKey, Opts) ->
    q(Table, HashKey, Opts, default_config()).

-spec q(table_name(), hash_key(), opts(), aws_config()) -> json_return().
q(Table, HashKey, Opts, Config) ->
    Json = [{<<"TableName">>, Table},
            hash_key_json(HashKey)] 
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.Query", Json).


-spec scan(table_name()) -> json_return().
scan(Table) ->
    scan(Table, [], default_config()).

-spec scan(table_name(), opts()) -> json_return().
scan(Table, Opts) ->
    scan(Table, Opts, default_config()).

-spec scan(table_name(), opts(), aws_config()) -> json_return().
scan(Table, Opts, Config) ->
    Json = [{<<"TableName">>, Table}]
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.Scan", Json).


-spec update_item(table_name(), key(), updates()) -> json_return().
update_item(Table, Key, Updates) ->
    update_item(Table, Key, Updates, [], default_config()).

-spec update_item(table_name(), key(), updates(), opts()) -> json_return().
update_item(Table, Key, Updates, Opts) ->
    update_item(Table, Key, Updates, Opts, default_config()).

-spec update_item(table_name(), key(), updates(), opts(), aws_config()) -> json_return().
update_item(Table, Key, Updates, Opts, Config) ->
    Json = [{<<"TableName">>, Table},
            key_json(Key),
            updates_json(Updates)] 
        ++ Opts,
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.UpdateItem", Json).

    
-spec update_table(table_name(), non_neg_integer(), non_neg_integer()) -> json_return().
update_table(Table, ReadUnits, WriteUnits) ->
    update_table(Table, ReadUnits, WriteUnits, default_config()).

-spec update_table(table_name(), non_neg_integer(), non_neg_integer(), aws_config()) -> json_return().
update_table(Table, ReadUnits, WriteUnits, Config) ->
    Json = [{<<"TableName">>, Table},
            {<<"ProvisionedThroughput">>, [{<<"ReadCapacityUnits">>, ReadUnits},
                                           {<<"WriteCapacityUnits">>, WriteUnits}]}],
    erlcloud_ddb_impl:request(Config, "DynamoDB_20111205.UpdateTable", Json).

%% backoff and retry are here for backwards compat. Use the ones in erlcloud_ddb_impl instead.

-define(NUM_ATTEMPTS, 10).

%% Sleep after an attempt
-spec backoff(pos_integer()) -> ok.
backoff(1) -> ok;
backoff(Attempt) -> 
    timer:sleep(random:uniform((1 bsl (Attempt - 1)) * 100)).

-type attempt() :: {attempt, pos_integer()} | {error, term()}.
-type retry_fun() :: fun((pos_integer(), term()) -> attempt()).
-spec retry(pos_integer(), term()) -> attempt().
retry(Attempt, Reason) when Attempt >= ?NUM_ATTEMPTS ->
    {error, Reason};
retry(Attempt, _) ->
    backoff(Attempt),
    {attempt, Attempt + 1}.
    
-type headers() :: [{string(), string()}].
-spec request_and_retry(aws_config(), headers(), jsx:json_text(), attempt()) -> 
                               {ok, jsx:json_term()} | {error, term()}.
request_and_retry(_, _, _, {error, Reason}) ->
    {error, Reason};
request_and_retry(Config, Headers, Body, {attempt, Attempt}) ->
    RetryFun = Config#aws_config.ddb_retry,
    case httpc:request(post, {url(Config), Headers, "application/x-amz-json-1.0", Body}, 
                       [{timeout, 1000}], 
                       [{body_format, binary}]) of

        {ok, {{_, 200, _}, _, RespBody}} ->
            %% TODO check crc
            {ok, jsx:decode(RespBody)};

        {ok, {{_, Status, StatusLine}, _, RespBody}} when Status >= 400 andalso Status < 500 ->
            case client_error(Status, StatusLine, RespBody) of
                {retry, Reason} ->
                    request_and_retry(Config, Headers, Body, RetryFun(Attempt, Reason));
                {error, Reason} ->
                    {error, Reason}
            end;
                            
        {ok, {{_, Status, StatusLine}, _, RespBody}} when Status >= 500 ->
            request_and_retry(Config, Headers, Body, RetryFun(Attempt, {http_error, Status, StatusLine, RespBody}));
                            
        {ok, {{_, Status, StatusLine}, _, RespBody}} ->
            {error, {http_error, Status, StatusLine, RespBody}};
                            
        {error, Reason} ->
            %% TODO there may be some http errors, such as certificate error, that we don't want to retry
            request_and_retry(Config, Headers, Body, RetryFun(Attempt, Reason))
    end.

-spec client_error(pos_integer(), string(), binary()) -> {retry, term()} | {error, term()}.
client_error(Status, StatusLine, Body) ->
    case jsx:is_json(Body) of
        false ->
            {error, {http_error, Status, StatusLine, Body}};
        true ->
            Json = jsx:decode(Body),
            case proplists:get_value(<<"__type">>, Json) of
                undefined ->
                    {error, {http_error, Status, StatusLine, Body}};
                FullType ->
                    Message = proplists:get_value(<<"message">>, Json, <<>>),
                    case binary:split(FullType, <<"#">>) of
                        [_, <<"ProvisionedThroughputExceededException">> = Type] ->
                            {retry, {Type, Message}};
                        [_, <<"ThrottlingException">> = Type] ->
                            {retry, {Type, Message}};
                        [_, Type] ->
                            {error, {Type, Message}};
                        _ ->
                            {error, {http_error, Status, StatusLine, Body}}
                    end
            end
    end.

-spec headers(aws_config(), string(), binary()) -> headers().
headers(Config, Operation, Body) ->
    Date = httpd_util:rfc1123_date(erlang:localtime()),
    Headers = [{"x-amz-date", Date},
               {"x-amz-target", "DynamoDB_20111205." ++ Operation}]
        ++ case Config#aws_config.security_token of
               undefined -> [];
               SecurityToken -> [{"x-amz-security-token", SecurityToken}]
           end,
    Authorization = authorization(Config, Headers, Body),
    [{"x-amzn-authorization", Authorization} | Headers].

%% TODO switch to AWS4 authorization
authorization(Config, Headers, Body) ->
    Signature = signature(Config, Headers, Body),
    lists:flatten(io_lib:format("AWS3 AWSAccessKeyId=~s,Algorithm=HmacSHA1,Signature=~s", 
                                [Config#aws_config.access_key_id, Signature])).

signature(Config, Headers, Body) ->
    StringToSign = lists:flatten(["POST", $\n, "/", $\n, $\n, canonical(Config, Headers), $\n, Body]),
    BytesToSign = crypto:hash(sha, StringToSign),
    base64:encode_to_string(binary_to_list(crypto:hmac(sha, Config#aws_config.secret_access_key, BytesToSign))).

canonical(Config, Headers) ->
    Headers1 = lists:map(fun({K, V}) -> {string:to_lower(K), V} end, Headers),
    Amz = lists:filter(fun({K, _V}) -> lists:prefix("x-amz-", K) end, Headers1),
    Headers2 = [{"host", Config#aws_config.ddb_host} | lists:sort(Amz)],
    [[K, $:, V, $\n] || {K, V} <- Headers2].

url(#aws_config{ddb_scheme = Scheme, ddb_host = Host} = Config) ->
    lists:flatten([Scheme, Host, port_spec(Config)]).

port_spec(#aws_config{ddb_port=80}) ->
    "";
port_spec(#aws_config{ddb_port=Port}) ->
    [":", erlang:integer_to_list(Port)].

default_config() -> erlcloud_aws:default_config().

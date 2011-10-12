#!/usr/bin/perl
use strict;
use warnings;
use Test::Most;
use Data::Dumper;
use Business::OnlinePayment;
  
#########################################################################################################
# setup
#########################################################################################################
bail_on_fail; 
    ok($ENV{OGONE_USERID}, "test can only proceed with environment OGONE_USERID set");
bail_on_fail; 
    ok($ENV{OGONE_PSPID}, "test can only proceed with environment OGONE_PSPID set");
bail_on_fail; 
    ok($ENV{OGONE_PSWD}, "test can only proceed with environment OGONE_PSWD set");

my $in = 'abc'.time;
my %base_args = (
    PSPID => $ENV{OGONE_PSPID},
    login => $ENV{OGONE_USERID},
    password => $ENV{OGONE_PSWD},
    action => 'authorization only',
    invoice_number => $in,
    amount      => '0.01',
    card_number => '4000 0000 0000 0002',
    cvc => '423',
    expiration  => '12/15',
    country => 'BE',
    address => 'Nieuwstraat 32',
    name => 'Alias Recurrent Customer',
    alias => 'customer_recur',
    sha_key => '___testing_123_passphrase___',
    sha_type => 512,
);

my %alias_args = (
    PSPID => $ENV{OGONE_PSPID},
    login => $ENV{OGONE_USERID},
    password => $ENV{OGONE_PSWD},
    action => 'recurrent authorization',
    cvc => '423',
    subscription_id => time + 1, # will differ from above time statment
    invoice_number => $in . 12,
    subscription_orderid => 'foobar',
    eci => '9',
    amount      => '10',
    startdate => '01/01/2010',
    enddate => '01/01/2011',
    status => 1,
    comment => 'test',
    period_unit => 'm',
    period_moment => 1,
    period_number => 1,
    alias => 'customer_recur',
    sha_key => '___testing_123_passphrase___',
    sha_type => 512,
);

sub new_test_tx {
    my $tx = new Business::OnlinePayment('Ogone');
    $tx->test_transaction(1);
    return $tx;
}

my $tx = new_test_tx();

#########################################################################################################
# test setup
#########################################################################################################
isa_ok($tx,'Business::OnlinePayment');

#########################################################################################################
# test recur flow: direct sale which also creates alias, and a recur call to that alias
#########################################################################################################
$tx = new_test_tx();

    $tx->content(%base_args); eval { $tx->submit() }; # diag(Dumper($tx->http_args));
    is($@, '', "there should have been no warnings");
    is($tx->is_success, 1, "must be successful");
        diag explain { req => $tx->http_args, res => $tx->result_xml};
    is($tx->error_message, undef, "error message must be undef");
    ok($tx->result_code == 0, "result_code should return 0");

$tx = new_test_tx();

    $tx->content(%alias_args); eval { $tx->submit() };  diag(Dumper($tx->http_args));
    is($@, '', "there should have been no warnings");
    is($tx->is_success, 1, "must be successful");
        diag explain { req => $tx->http_args, res => $tx->result_xml};
    is($tx->error_message, undef, "error message must be undef");
    ok($tx->result_code == 0, "result_code should return 0");


done_testing();

__END__

data capture:

CH_Email    
CH_Telno    
CH_name foo
CSRFKEY 721BE764648C22418D6723FECE46AE422CB6537A
CSRFSP  /ncol/test/edit_merchsubscriptions.asp
CSRFTS  20111012190745
Ecom_Payment_Card_ExpDate...    12
Ecom_Payment_Card_ExpDate...    2015
Ecom_Payment_Card_Number    4000 0000 0000 0002
PM  CC
SUB_period_moment_m 1
SUB_period_moment_ww    1
SUB_period_number_d 
SUB_period_number_m 1
SUB_period_number_ww    
SUB_period_unit m
Sub_COM 
Sub_Enddate 01/01/2012
Sub_Startdate   01/10/2011
Sub_am  120.00
Sub_cur EUR
Sub_orderid 01/01/2011
account_Number  
create  Create
sub_comment 
sub_status  0
subscription_id 123333





AM  99.00
BRANDING    OGONE
COM description field
CUR EUR
CVCFlag -1
Comp_Expirydate 201512
Ecom_Payment_Card_Verific...    423
OID 123456
SelOperation    
Tn1 
Tn2 
Track1  
Track2  
cardname    Test
cardnumber  4000000000000002
eci 9
exp02   12
exp03   15
merchalias  
ownerZIP    1000
owneraddress    foostreet
storealias  1
submit  Submit

Source
Content-Type: application/x-www-form-urlencoded Content-Length: 315 BRANDING=OGONE&cardname=Test&cardnumber=4000000000000002&merchalias=&storealias=1&exp02=12&exp03=15&Comp_Expirydate=201512&Ecom_Payment_Card_Verification=423&CVCFlag=-1&eci=9&SelOperation=&owneraddress=foostreet&ownerZIP=1000&OID=123456&CUR=EUR&AM=99.00&submit=Submit&COM=description+field&Track2=&Track1=&Tn1=&Tn2=


# vim: ft=perl

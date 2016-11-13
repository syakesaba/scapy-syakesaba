#!/usr/bin/env python
# encoding: utf-8

from scapy.packet import Packet, bind_layers
from scapy.fields import *


class Example(Packet):  # 必ずPacketクラスを継承すること
    """
    Scapyに自作プロトコルを実装するためのモデルです。
    Packetクラスは基本的に受信した1つのパケットデータのすべてを常に保持します。
    """
    name = "ProtocolName"  # ls()で表示されるプロトコルの説明文。クラス名と一致させる必要はない。
    fields_desc = [
        ByteEnumField("code", 0, {1: "code1!", 2: "code2!!", 3: "code3!!!", 0xFF: "OMG"}),
    ]  # 前から順にバイト列が決まるので注意
    aliastypes = []  # プロトコルエイリアス。ほとんどの場合使わない。
    overload_fields = {}  # ペイロードプロトコルから値を継承するフィールドを宣言できる
    payload_guess = []  # ペイロードプロトコルの候補をあらかじめ定義可能

    # Dissecting関係
    #   NICやファイルからパケットを読み込んだときにhookする関数群
    #   アナライザとしての役割を果たす
    #   元となるのはdissect関数である。
    #   *snip*
    #    def dissect(self, s):
    #        s = self.pre_dissect(s)
    #        s = self.do_dissect(s)
    #        s = self.post_dissect(s)
    #        payl,pad = self.extract_padding(s)
    #        self.do_dissect_payload(payl)
    #        if pad and conf.padding:
    #            self.add_payload(conf.padding_layer(pad))

    def pre_dissect(self, s):
        """
        この関数はパケットの解析の準備を担います。オーバーライドしなければ何もしません。
        この関数ではFCSのチェックとか、パケットの長さのチェック、
        その他、パケットの解析の前にすべきことを行います。
        @param s str 受信したバイト列全文。
        @return s str do_dissectにたらい回すバイト列全文
        """
        return Packet.pre_dissect(self, s)

    def do_dissect(self, s):
        """
        この関数はパケットの解析の中核を担います。オーバーライドしなければ
        fields_descに沿った解析がいい感じに自動でなされます。
        @param s str pre_dieectからたらい回されたバイト列。
        @return s str post_dissectにたらい回すバイト列全文
        """
        return Packet.do_dissect(self, s)

    def post_dissect(self, s):
        """
        この関数はパケットの解析の後始末を担います。オーバーライドしなければ何もしません。
        この関数ではデータ解析後の完全性のチェックや内包圧縮データの展開を行います。
        @param s str do_dieectからたらい回されたバイト列。
        @return s str extract_paddingにたらい回すバイト列全文
        """
        return Packet.post_dissect(self, s)

    def extract_padding(self, s):
        """
        この関数ではパケット解析の後発生した
        ペイロード(next layer)とパディング(Padding)を2つに分断します。
        パディングが無ければpay,Noneをreturnすること。
        @param s str pre_dissectで返されたバイト列。(分割前のデータ)
        @return pay str ペイロード部。guess_payload_classに渡される
        @return pad str パディング部。Paddingクラスに渡される
        """
        return Packet.extract_padding(self, s)  # return pay,pad

    def post_dissection(self, pkt):
        """
        下位・上位のパケットの全てが解析完了した場合に下位レイヤから実行される関数
        @param pkt Packet 解析済の全体パケット
        @return None 何も返してはいけません。
        """
        pass

    def dissection_done(self, pkt):
        """
        基本的にいじってはいけない。
        :param pkt: 解析済パケット
        :return: None 何も返してはいけません。
        """
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)


    # Building:
    #   パケットを送信するときなど、パケットを完成させるための関数群
    #   与えられた文字や数字をmachine語(バイナリ)になおす。
    # 元となるのはbuild関数である。
    # ****最も重要なのはpost_build関数である。
    #    def build(self):
    #        p = self.do_build()
    #        p += self.build_padding()
    #        p = self.build_done(p)
    #        return p
    #    def do_build(self):
    #        if not self.explicit:
    #            self = self.__iter__().next()
    #        pkt = self.self_build()
    #        for t in self.post_transforms:
    #            pkt = t(pkt)
    #        pay = self.do_build_payload()
    #        p = self.post_build(pkt,pay)
    #        return p
    def self_build(self, field_post_list=[]):
        """
        デフォルトで、パケットを構成するfields_descの各フィールドを順にi2mしていく。
        その後、fuzzing用のtransform系関数が呼ばれ、晴れて一つのpktになる。
        @param field_post_list list 知らん
        @return pkt str 各フィールドをi2mした後のパケットのバイナリ文字列
        """
        return Packet.self_build(self, field_post_list)

    def do_build_payload(self):
        """
        ペイロードに対してdo_build_payload関数を呼び出す。
        デフォルトでペイロードで連鎖する。
        @return pay str 連鎖して完成した自レイヤ以降のペイロード
        """
        return Packet.do_build_payload(self)

    def post_build(self, pkt, pay):
        """
        自レイヤ以降すべてのペイロードが計算された後呼ばれる。
        pktはこのクラスのテキストデータであり、payはペイロード部である。
        この関数ではCRCなどのチェックサムを計算したり、
        lengthを代入するフィールドの計算をするべきである。
        大抵この関数を実装しないとロクに送受信できない。
        この関数の時点でselfには完成間近のパケットクラスが入っているので
        fields_descのフィールド名でフィールドにアクセスできる。
        各フィールドの値で埋められていないところをこの関数で埋めるが、
        その際selfは編集せず、pktの方を編集すること。
        payは基本編集しないはず。
        @param pkt str パケットデータ。
        @param pay str パケットデータ。最後にpkt+payするために使う。
        @return p str パケットデータ。多くの場合pkt+payをreturnするだろう。
        """
        self.show()
        print "===pkt==="
        print pkt
        print "===pay==="
        print pay
        return Packet.post_build(self, pkt, pay)

    def build_padding(self):
        """
        ペイロードに対してbuild_padding関数を呼び出す。
        デフォルトでペイロードで連鎖する。
        @return pad str 連鎖して完成した自レイヤ以降のパディング
        """
        return Packet.build_padding(self)

    def build_done(self, pkt):
        """
        ペイロードに対してbuild_done関数を呼び出す。
        デフォルトでペイロードで連鎖する。
        @return pkt str 最終的に完成した全パケットデータ
        """
        return Packet.build_done(self, pkt)

    # Binding:
    # Dissectingの際に使用される関数群。
    # プロトコルとプロトコルを接続するために使用する。
    # よほどのことがない限りpayload_guessパラメタやbind_layersによるbindingの方を推奨する
    #    @conf.commands.register
    #    def bind_layers(lower, upper, __fval=None, **fval):
    #        """Bind 2 layers on some specific fields' values"""
    #        if __fval is not None:
    #            fval.update(__fval)
    #        bind_top_down(lower, upper, **fval)
    #        bind_bottom_up(lower, upper, **fval)
    # bind_layers()

    def guess_payload_class(self, pay):
        """
        この関数ではこのクラスのペイロード部のプロトコルを判定し、
        そのプロトコルを解析しうるクラスオブジェクトを返します。
        この関数の中で複雑なペイロード識別を行うことができます。
        Note:
        TCPの宛先ポート番号80番はHTTPクラス、というように
        このPacketのペイロードのプロトコルがこのPacketのfields_descの値によって
        即座に決定する場合、bind_layersに頼るべきです。
        (オーバーライドしない場合の標準仕様です。)
        @param pay str extract_paddingで渡されたペイロード。
        @return pktClass class 推測判定したペイロードプロトコルクラス。Packetクラスを継承していること。
        """
        return Packet.guess_payload_class(self, pay)  # bind_layers関数による紐付けに頼ります。

    def default_payload_class(self, pay):
        """
        guess_payload_classでペイロードのプロトコルが推測できない場合に呼び出されます。
        ただし、同関数をあなたがオーバーライドしていた場合、関数の中でこの関数を
        処理の最後にreturnとして明示的に呼び出す必要があります。
        本来Rawクラスがデフォルトのプロトコルですが、この関数をオーバーロードすることで
        異なるデフォルトのプロトコルを指定できます。あまり使いません。
        @param pay str extract_paddingで渡されたペイロード。
        @return pktClass class 推測判定したペイロードプロトコルクラス。Packetクラスを継承していること。
        """
        return Packet.default_payload_class(self, pay)

    # Misc
    # その他の機能的な関数群。実装はMUSTではない。

    def get_field(self, fld):
        """
        プロトコル書いた後になくなくパラメタのget時にhookして細工しないと行けなくなった時に使用する。
        基本的に使うシーンは存在しない
        :param fld: Field
        :return: object value
        """
        return self.fieldtype[fld]

    def hashret(self):
        """
        ほぼ使わない。実装は不要
        """
        return self.payload.hashret()

    def answers(self, other):
        """
        srなどで送ったパケットの応答かどうかをこの関数を使って判別する。
        selfが送ったパケットでotherが受け取ったパケット。
        :param other: Recv Packet
        :return: 0 if different else 1
        """
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        """
        自由に上書き宣言して好きな方式で出力する関数
        :return: str
        """
        return ""


if __name__ == "__main__":
    i = Example()
    i.code = 0xFF
    i.show()
    from scapy.main import interact
    interact(mydict=locals())

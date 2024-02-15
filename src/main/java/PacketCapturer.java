import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 根据设定时间进行一段时间的数据包捕获并分析
 */
public class PacketCapturer {
    private int time; // 捕获时长，单位为秒
    private final List<Packet> packets; // 存储捕获的数据包
    private int chosenIfs; //监听的网卡设备序号
    private PcapHandle handle;

    public PacketCapturer(int time,int ifsNum) {
        this.time = time;
        this.chosenIfs = ifsNum;
        this.packets = new ArrayList<>();
    }

    /**
     * 开始捕获，捕获时长为time秒
     *
     * @throws PcapNativeException
     * @throws InterruptedException
     * @throws NotOpenException
     */
    public void startCapture() throws PcapNativeException, InterruptedException, NotOpenException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs.isEmpty() || chosenIfs >= allDevs.size() || chosenIfs < 0) {
            System.out.println("选择的网卡不存在");
            return;
        }
        PcapNetworkInterface device = allDevs.get(chosenIfs);

        this.handle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        // 使用独立线程进行数据包捕获
        Thread captureThread = new Thread(() -> {
            try {
                this.handle.loop(-1, (PacketListener) packet -> packets.add(packet));
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }catch (InterruptedException e) {
                // 这里不需要做额外的操作，因为中断是由breakLoop()方法触发的预期行为
                System.out.println("数据包捕获已结束，捕获时长"+time+"秒");
            }
        });
        captureThread.start();

        // 指定时间后停止捕获
        Thread.sleep(time * 1000L);
        this.handle.breakLoop();

        // 等待捕获线程结束
        captureThread.join();

        this.handle.close();
    }

    /**
     * 返回捕获到数据包的数量
     * @return
     */
    public int getTotalPacketsCaptured() {
        return packets.size();
    }

    public static void main(String[] args) throws IOException, NotOpenException, PcapNativeException, InterruptedException {
        PacketCapturer capturer = new PacketCapturer(10,10); // 设置捕获时长为10秒
        capturer.startCapture();
        System.out.println("总共捕获到的数据包数量: " + capturer.getTotalPacketsCaptured());
    }
}

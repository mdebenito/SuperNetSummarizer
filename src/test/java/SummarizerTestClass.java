import org.junit.Test;
import supernetsummarizer.SuperNetSummarizer;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Class that tests the summarizer library with some mock IP ranges.
 */
public class SummarizerTestClass {
    @Test
    public void summarizeTest(){
        //Generate IP Ranges
        List<String> ips = new ArrayList<>();

        // /24
        for(int i=1; i <255; i++)
            ips.add("10.203.205."+i);
        // /25
        for(int i=1;i<127;i++)
            ips.add("192.168.1."+i);

        // /26
        for(int i=65;i<127;i++)
            ips.add("10.30.100."+i);

        // lonely boy
        ips.add("200.12.1.1");

        //weird range
        for(int i=45;i<125;i++)
            ips.add("10.10.10."+i);

        try {
            List <String> summarized = SuperNetSummarizer.summarize(ips);
            System.out.println(summarized.size());

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }


    }
}

import org.junit.Test;
import supernetsummarizer.SuperNetSummarizer;

import java.io.*;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

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
            assertEquals("Number of ranges/IPs",22,summarized.size());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void summarizeBigListTest(){
        File dir = new File("input/");
        File file = new File(dir,"input.dat");

        List<String> ips = new ArrayList<>();
        List <String> summarized = new ArrayList<>();

        if(file.exists()){
            try {
                try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        ips.add(line);
                    }

                    summarized = SuperNetSummarizer.summarize(ips);

                }


                File outfile = new File(dir,"output.dat");

                FileWriter fw = new FileWriter(outfile);

                for (String s : summarized) {
                    fw.write(s+System.getProperty("line.separator"));
                }

                fw.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }
}

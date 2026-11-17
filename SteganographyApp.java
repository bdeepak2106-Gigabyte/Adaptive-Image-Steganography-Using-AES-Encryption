import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * SteganographyApp
 * -----------------
 * A simple desktop tool to hide and reveal text messages inside PNG images
 * using LSB (Least Significant Bit) steganography, with optional
 * password-based AES encryption of the message before hiding.
 *
 * Compile:  javac SteganographyApp.java
 * Run:      java SteganographyApp
 */
public class SteganographyApp extends JFrame {

    public SteganographyApp() {
        super("Hidden Channel — Image Steganography");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(980, 760);
        setLocationRelativeTo(null);
        setMinimumSize(new Dimension(820, 650));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Hide Message", new HidePanel());
        tabs.addTab("Reveal Message", new RevealPanel());
        tabs.addTab("Technical Details", new TechnicalPanel());
        add(tabs);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) { }
            new SteganographyApp().setVisible(true);
        });
    }

    // =========================================================
    //  CORE STEGANOGRAPHY LOGIC
    // =========================================================
    static class Stego {

        // Adaptive format: 4-byte magic + 4-byte payload length + payload.
        private static final byte[] ADAPTIVE_MAGIC = {'A', 'L', 'S', '1'};
        private static final int EDGE_THRESHOLD = 24;

        /** Returns the legacy sequential LSB capacity in bytes. */
        static int capacityBytes(BufferedImage img) {
            long usableBits = (long) img.getWidth() * img.getHeight() * 3;
            return (int) Math.max(0, usableBits / 8 - 4);
        }

        /**
         * Adaptive capacity. Only pixels in high-contrast/edge regions are used.
         * Three LSBs are available per selected pixel (R, G and B).
         */
        static int adaptiveCapacityBytes(BufferedImage img) {
            int edgePixels = countAdaptivePixels(img);
            return Math.max(0, edgePixels * 3 / 8 - 8); // 4-byte magic + 4-byte length
        }

        /** Hides a message using the original sequential LSB method. */
        static BufferedImage encodeLegacy(BufferedImage source, String message, String password) throws Exception {
            byte[] payload = message.getBytes(StandardCharsets.UTF_8);
            if (password != null && !password.isEmpty()) {
                payload = aesEncrypt(payload, password);
            }

            int len = payload.length;
            byte[] full = new byte[4 + len];
            full[0] = (byte) (len >>> 24);
            full[1] = (byte) (len >>> 16);
            full[2] = (byte) (len >>> 8);
            full[3] = (byte) len;
            System.arraycopy(payload, 0, full, 4, len);

            int neededBits = full.length * 8;
            int capacityBits = source.getWidth() * source.getHeight() * 3;
            if (neededBits > capacityBits) {
                throw new IllegalArgumentException("Message too large for this image. "
                        + "Max is " + capacityBytes(source) + " bytes, message needs " + len + " bytes.");
            }

            BufferedImage out = copyImage(source);
            boolean[] bits = toBits(full);
            int bitIndex = 0;

            outer:
            for (int y = 0; y < source.getHeight(); y++) {
                for (int x = 0; x < source.getWidth(); x++) {
                    int argb = source.getRGB(x, y);
                    int a = (argb >>> 24) & 0xFF;
                    int r = (argb >>> 16) & 0xFF;
                    int g = (argb >>> 8) & 0xFF;
                    int b = argb & 0xFF;

                    if (bitIndex < bits.length) r = setLsb(r, bits[bitIndex++]);
                    if (bitIndex < bits.length) g = setLsb(g, bits[bitIndex++]);
                    if (bitIndex < bits.length) b = setLsb(b, bits[bitIndex++]);

                    out.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);

                    if (bitIndex >= bits.length) break outer;
                }
            }
            return out;
        }

        /**
         * Adaptive LSB:
         * 1. Calculate local contrast for each pixel.
         * 2. Keep pixels whose contrast is above EDGE_THRESHOLD.
         * 3. Hide the encrypted payload only in those pixels.
         *
         * Edge/texture regions tolerate tiny LSB changes better than large smooth areas.
         */
        static BufferedImage encodeAdaptive(BufferedImage source, String message, String password) throws Exception {
            byte[] payload = message.getBytes(StandardCharsets.UTF_8);
            if (password != null && !password.isEmpty()) {
                payload = aesEncrypt(payload, password);
            }

            byte[] full = new byte[8 + payload.length];
            System.arraycopy(ADAPTIVE_MAGIC, 0, full, 0, 4);
            int len = payload.length;
            full[4] = (byte) (len >>> 24);
            full[5] = (byte) (len >>> 16);
            full[6] = (byte) (len >>> 8);
            full[7] = (byte) len;
            System.arraycopy(payload, 0, full, 8, payload.length);

            boolean[] bits = toBits(full);
            int availableBits = countAdaptivePixels(source) * 3;

            if (bits.length > availableBits) {
                throw new IllegalArgumentException(
                        "Message is too large for Adaptive LSB. "
                        + "Adaptive capacity is " + adaptiveCapacityBytes(source)
                        + " bytes, but the encrypted message needs " + payload.length + " bytes.");
            }

            BufferedImage out = copyImage(source);
            int bitIndex = 0;

            for (int y = 0; y < source.getHeight(); y++) {
                for (int x = 0; x < source.getWidth(); x++) {
                    if (!isAdaptivePixel(source, x, y)) continue;

                    int argb = out.getRGB(x, y);
                    int a = (argb >>> 24) & 0xFF;
                    int r = (argb >>> 16) & 0xFF;
                    int g = (argb >>> 8) & 0xFF;
                    int b = argb & 0xFF;

                    if (bitIndex < bits.length) r = setLsb(r, bits[bitIndex++]);
                    if (bitIndex < bits.length) g = setLsb(g, bits[bitIndex++]);
                    if (bitIndex < bits.length) b = setLsb(b, bits[bitIndex++]);

                    out.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);

                    if (bitIndex >= bits.length) return out;
                }
            }

            throw new IllegalStateException("Adaptive embedding could not complete.");
        }

        /** Automatically decodes both new Adaptive LSB images and old sequential-LSB images. */
        static String decode(BufferedImage img, String password) throws Exception {
            try {
                return decodeAdaptive(img, password);
            } catch (Exception adaptiveFailure) {
                // Backward compatibility with images created by the original version.
                return decodeLegacy(img, password);
            }
        }

        private static String decodeAdaptive(BufferedImage img, String password) throws Exception {
            int availableBits = countAdaptivePixels(img) * 3;
            if (availableBits < 64) {
                throw new IllegalStateException("No Adaptive LSB message found.");
            }

            boolean[] headerBits = new boolean[64];
            readAdaptiveBits(img, headerBits, 0);
            byte[] header = fromBits(headerBits);

            for (int i = 0; i < 4; i++) {
                if (header[i] != ADAPTIVE_MAGIC[i]) {
                    throw new IllegalStateException("Not an Adaptive LSB image.");
                }
            }

            int len = ((header[4] & 0xFF) << 24)
                    | ((header[5] & 0xFF) << 16)
                    | ((header[6] & 0xFF) << 8)
                    | (header[7] & 0xFF);

            int maxPossible = adaptiveCapacityBytes(img);
            if (len <= 0 || len > maxPossible) {
                throw new IllegalStateException("Invalid Adaptive LSB payload length.");
            }

            boolean[] msgBits = new boolean[len * 8];
            readAdaptiveBits(img, msgBits, 64);
            byte[] payload = fromBits(msgBits);

            if (password != null && !password.isEmpty()) {
                try {
                    payload = aesDecrypt(payload, password);
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "Wrong password, or this image has no encrypted message.");
                }
            }

            return new String(payload, StandardCharsets.UTF_8);
        }

        private static String decodeLegacy(BufferedImage img, String password) throws Exception {
            int totalBits = img.getWidth() * img.getHeight() * 3;
            if (totalBits < 32) throw new IllegalStateException("Image too small to contain a message.");

            boolean[] lengthBits = new boolean[32];
            readBits(img, lengthBits, 0);
            int len = fromBits32(lengthBits);

            int maxPossible = capacityBytes(img);
            if (len <= 0 || len > maxPossible) {
                throw new IllegalStateException("No hidden message found in this image.");
            }

            boolean[] msgBits = new boolean[len * 8];
            readBits(img, msgBits, 32);
            byte[] payload = fromBits(msgBits);

            if (password != null && !password.isEmpty()) {
                try {
                    payload = aesDecrypt(payload, password);
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "Wrong password, or this image has no encrypted message.");
                }
            }

            return new String(payload, StandardCharsets.UTF_8);
        }

        /** Determines whether a pixel is in a high-contrast/edge region. */
        private static boolean isAdaptivePixel(BufferedImage img, int x, int y) {
            int center = luminance(img.getRGB(x, y));
            int sum = 0;
            int count = 0;

            if (x > 0) {
                sum += luminance(img.getRGB(x - 1, y));
                count++;
            }
            if (x < img.getWidth() - 1) {
                sum += luminance(img.getRGB(x + 1, y));
                count++;
            }
            if (y > 0) {
                sum += luminance(img.getRGB(x, y - 1));
                count++;
            }
            if (y < img.getHeight() - 1) {
                sum += luminance(img.getRGB(x, y + 1));
                count++;
            }

            int neighborAverage = sum / Math.max(1, count);
            int contrast = Math.abs(center - neighborAverage);
            return contrast >= EDGE_THRESHOLD;
        }

        static List<Point> adaptivePixels(BufferedImage img) { List<Point> out=new ArrayList<Point>(); for(int y=0;y<img.getHeight();y++) for(int x=0;x<img.getWidth();x++) if(isAdaptivePixel(img,x,y)) out.add(new Point(x,y)); return out; }

        private static int countAdaptivePixels(BufferedImage img) {
            int count = 0;
            for (int y = 0; y < img.getHeight(); y++) {
                for (int x = 0; x < img.getWidth(); x++) {
                    if (isAdaptivePixel(img, x, y)) count++;
                }
            }
            return count;
        }

        private static int luminance(int argb) {
            int r = (argb >>> 16) & 0xFF;
            int g = (argb >>> 8) & 0xFF;
            int b = argb & 0xFF;
            return (299 * r + 587 * g + 114 * b) / 1000;
        }

        private static BufferedImage copyImage(BufferedImage source) {
            BufferedImage out = new BufferedImage(
                    source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_ARGB);
            for (int y = 0; y < source.getHeight(); y++) {
                for (int x = 0; x < source.getWidth(); x++) {
                    out.setRGB(x, y, source.getRGB(x, y));
                }
            }
            return out;
        }

        private static int setLsb(int channel, boolean bit) {
            return (channel & 0xFE) | (bit ? 1 : 0);
        }

        private static boolean[] toBits(byte[] bytes) {
            boolean[] bits = new boolean[bytes.length * 8];
            int i = 0;
            for (byte bt : bytes) {
                for (int b = 7; b >= 0; b--) {
                    bits[i++] = ((bt >>> b) & 1) == 1;
                }
            }
            return bits;
        }

        private static byte[] fromBits(boolean[] bits) {
            byte[] out = new byte[bits.length / 8];
            for (int i = 0; i < out.length; i++) {
                int val = 0;
                for (int b = 0; b < 8; b++) {
                    val = (val << 1) | (bits[i * 8 + b] ? 1 : 0);
                }
                out[i] = (byte) val;
            }
            return out;
        }

        private static int fromBits32(boolean[] bits) {
            int val = 0;
            for (int i = 0; i < 32; i++) val = (val << 1) | (bits[i] ? 1 : 0);
            return val;
        }

        private static void readAdaptiveBits(BufferedImage img, boolean[] dest, int skipBits) {
            int idx = 0;
            int collected = 0;

            outer:
            for (int y = 0; y < img.getHeight(); y++) {
                for (int x = 0; x < img.getWidth(); x++) {
                    if (!isAdaptivePixel(img, x, y)) continue;

                    int argb = img.getRGB(x, y);
                    int[] channels = {
                            (argb >>> 16) & 0xFF,
                            (argb >>> 8) & 0xFF,
                            argb & 0xFF
                    };

                    for (int c : channels) {
                        if (idx++ < skipBits) continue;
                        dest[collected++] = (c & 1) == 1;
                        if (collected >= dest.length) break outer;
                    }
                }
            }

            if (collected < dest.length) {
                throw new IllegalStateException("Adaptive data is incomplete or corrupted.");
            }
        }

        private static void readBits(BufferedImage img, boolean[] dest, int skipBits) {
            int idx = 0, collected = 0;
            outer:
            for (int y = 0; y < img.getHeight(); y++) {
                for (int x = 0; x < img.getWidth(); x++) {
                    int argb = img.getRGB(x, y);
                    int[] channels = {
                            (argb >>> 16) & 0xFF,
                            (argb >>> 8) & 0xFF,
                            argb & 0xFF
                    };
                    for (int c : channels) {
                        if (idx++ < skipBits) continue;
                        dest[collected++] = (c & 1) == 1;
                        if (collected >= dest.length) break outer;
                    }
                }
            }
        }

        // ---- AES helpers (password -> SHA-256 -> first 16 bytes as AES-128 key) ----
        private static SecretKeySpec keyFromPassword(String password) throws Exception {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(password.getBytes(StandardCharsets.UTF_8));
            byte[] key16 = new byte[16];
            System.arraycopy(hash, 0, key16, 0, 16);
            return new SecretKeySpec(key16, "AES");
        }

        private static byte[] aesEncrypt(byte[] data, String password) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyFromPassword(password));
            return cipher.doFinal(data);
        }

        private static byte[] aesDecrypt(byte[] data, String password) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyFromPassword(password));
            return cipher.doFinal(data);
        }
    }

    // =========================================================
    //  HIDE PANEL
    // =========================================================
    static class HidePanel extends JPanel {
        private BufferedImage loadedImage;
        private final JLabel imagePreview = new JLabel("No image selected", SwingConstants.CENTER);
        private final JTextArea messageArea = new JTextArea(6, 40);
        private final JPasswordField passwordField = new JPasswordField();
        private final JLabel capacityLabel = new JLabel("Upload an image first");
        private final JLabel remainingLabel = new JLabel("Characters remaining: —");
        private final JButton chooseBtn = new JButton("Choose Image...");
        private final JButton encodeBtn = new JButton("Hide Message & Save PNG");
        private final JCheckBox adaptiveBox = new JCheckBox("Use Adaptive LSB (recommended)", true);
        private final JLabel statusLabel = new JLabel(" ");

        HidePanel() {
            setLayout(new BorderLayout(10, 10));
            setBorder(new EmptyBorder(16, 16, 16, 16));

            imagePreview.setPreferredSize(new Dimension(300, 220));
            imagePreview.setBorder(BorderFactory.createLineBorder(Color.GRAY));

            JPanel top = new JPanel(new BorderLayout(8, 8));
            top.add(imagePreview, BorderLayout.CENTER);
            JPanel chooseRow = new JPanel(new BorderLayout(8, 4));
            chooseRow.add(chooseBtn, BorderLayout.WEST);

            JPanel capacityInfo = new JPanel(new GridLayout(2, 1));
            capacityInfo.add(capacityLabel);
            capacityInfo.add(remainingLabel);

            chooseRow.add(capacityInfo, BorderLayout.CENTER);
            top.add(chooseRow, BorderLayout.SOUTH);

            JPanel form = new JPanel();
            form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
            form.add(new JLabel("Secret message:"));
            messageArea.setLineWrap(true);
            messageArea.setWrapStyleWord(true);
            form.add(new JScrollPane(messageArea));
            form.add(Box.createVerticalStrut(10));
            form.add(new JLabel("Password (optional — encrypts the message with AES before hiding):"));
            form.add(passwordField);
            form.add(Box.createVerticalStrut(8));
            form.add(adaptiveBox);
            form.add(Box.createVerticalStrut(10));
            form.add(encodeBtn);
            form.add(Box.createVerticalStrut(6));
            statusLabel.setForeground(new Color(0, 120, 0));
            form.add(statusLabel);

            add(top, BorderLayout.NORTH);
            add(form, BorderLayout.CENTER);

            chooseBtn.addActionListener(this::onChooseImage);
            encodeBtn.addActionListener(this::onEncode);
            adaptiveBox.addActionListener(e -> updateRemainingCount());

            messageArea.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    updateRemainingCount();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    updateRemainingCount();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    updateRemainingCount();
                }
            });

            updateRemainingCount();
        }

        private void onChooseImage(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileFilter(new FileNameExtensionFilter("Images", "png", "jpg", "jpeg", "bmp"));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = chooser.getSelectedFile();
                    loadedImage = javax.imageio.ImageIO.read(file);
                    ImageIcon icon = new ImageIcon(loadedImage.getScaledInstance(300, 220, Image.SCALE_SMOOTH));
                    imagePreview.setIcon(icon);
                    imagePreview.setText(null);
                    capacityLabel.setText("Adaptive capacity: " + Stego.adaptiveCapacityBytes(loadedImage)
                            + " bytes | Legacy: " + Stego.capacityBytes(loadedImage) + " bytes");
                    updateRemainingCount();
                    statusLabel.setText(" ");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Could not load image: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }

        private void updateRemainingCount() {
            if (loadedImage == null) {
                remainingLabel.setText("Characters remaining: —");
                return;
            }

            int capacity = adaptiveBox.isSelected()
                    ? Stego.adaptiveCapacityBytes(loadedImage)
                    : Stego.capacityBytes(loadedImage);

            String message = messageArea.getText();
            int usedBytes = message.getBytes(StandardCharsets.UTF_8).length;
            int usedCharacters = message.codePointCount(0, message.length());
            int remainingBytes = capacity - usedBytes;

            if (remainingBytes >= 0) {
                remainingLabel.setText(
                        "Characters: " + usedCharacters
                                + " | Remaining capacity: " + remainingBytes + " bytes");
            } else {
                remainingLabel.setText(
                        "Characters: " + usedCharacters
                                + " | OVER CAPACITY by " + (-remainingBytes) + " bytes");
            }
        }

        private void onEncode(ActionEvent e) {
            if (loadedImage == null) {
                JOptionPane.showMessageDialog(this, "Please choose an image first.");
                return;
            }
            String message = messageArea.getText();
            if (message == null || message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please type a message to hide.");
                return;
            }
            String password = new String(passwordField.getPassword());

            try {
                BufferedImage result = adaptiveBox.isSelected()
                        ? Stego.encodeAdaptive(loadedImage, message, password)
                        : Stego.encodeLegacy(loadedImage, message, password);

                JFileChooser saveChooser = new JFileChooser();
                saveChooser.setSelectedFile(new File("hidden-message.png"));
                saveChooser.setFileFilter(new FileNameExtensionFilter("PNG Image", "png"));
                if (saveChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                    File outFile = saveChooser.getSelectedFile();
                    if (!outFile.getName().toLowerCase().endsWith(".png")) {
                        outFile = new File(outFile.getParentFile(), outFile.getName() + ".png");
                    }
                    javax.imageio.ImageIO.write(result, "png", outFile);
                    statusLabel.setText("✓ Saved: " + outFile.getName() + " — keep it as PNG, don't re-save as JPEG.");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // =========================================================
    //  TECHNICAL DETAILS PANEL
    // =========================================================
    static class TechnicalPanel extends JPanel {
        private BufferedImage image; private File imageFile;
        private final JLabel fileLabel=new JLabel("No image selected");
        private final JLabel imageInfo=new JLabel("Choose an image to inspect its technical details.");
        private final JLabel normalStats=new JLabel(), adaptiveStats=new JLabel(), securityStats=new JLabel();
        private final JTextArea explanation=new JTextArea(); private final JSlider amount=new JSlider(1,100,100);
        private final JLabel amountLabel=new JLabel("100% payload");
        private final PixelMapPanel normalMap=new PixelMapPanel("Normal LSB",false), adaptiveMap=new PixelMapPanel("Adaptive LSB",true);
        TechnicalPanel(){
            setLayout(new BorderLayout(10,10)); setBorder(new EmptyBorder(12,12,12,12));
            JPanel head=new JPanel(new BorderLayout(8,4)); JPanel h=new JPanel(); h.setLayout(new BoxLayout(h,BoxLayout.Y_AXIS));
            JLabel title=new JLabel("Technical Details — Selected Image"); title.setFont(title.getFont().deriveFont(Font.BOLD,20f));
            h.add(title); h.add(fileLabel); h.add(imageInfo); JButton choose=new JButton("Choose Image..."); head.add(h); head.add(choose,BorderLayout.EAST);
            JPanel maps=new JPanel(new GridLayout(1,2,10,10)); maps.add(normalMap); maps.add(adaptiveMap);
            JPanel cards=new JPanel(new GridLayout(1,3,8,8)); cards.add(card("NORMAL LSB",normalStats)); cards.add(card("ADAPTIVE LSB",adaptiveStats)); cards.add(card("IMAGE / SECURITY",securityStats));
            JPanel controls=new JPanel(new BorderLayout(8,4)); controls.add(new JLabel("Visualize payload amount:"),BorderLayout.WEST); controls.add(amount); controls.add(amountLabel,BorderLayout.EAST);
            explanation.setEditable(false); explanation.setLineWrap(true); explanation.setWrapStyleWord(true); explanation.setRows(3);
            JPanel bottom=new JPanel(new BorderLayout(8,8)); bottom.add(cards,BorderLayout.NORTH); bottom.add(controls,BorderLayout.CENTER); bottom.add(new JScrollPane(explanation),BorderLayout.SOUTH);
            add(head,BorderLayout.NORTH); add(maps,BorderLayout.CENTER); add(bottom,BorderLayout.SOUTH);
            choose.addActionListener(e->chooseImage()); amount.addChangeListener(e->{amountLabel.setText(amount.getValue()+"% payload");normalMap.setAmount(amount.getValue());adaptiveMap.setAmount(amount.getValue());}); clear();
        }
        JPanel card(String title,JLabel label){ JPanel p=new JPanel(new BorderLayout(4,4)); p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(190,190,205)),new EmptyBorder(8,8,8,8))); JLabel t=new JLabel(title);t.setFont(t.getFont().deriveFont(Font.BOLD));p.add(t,BorderLayout.NORTH);p.add(label,BorderLayout.CENTER);return p; }
        void clear(){normalStats.setText("<html>Select an image.</html>");adaptiveStats.setText("<html>Select an image.</html>");securityStats.setText("<html>Format: —<br>Encryption: AES optional</html>");explanation.setText("This tab is specific to the selected image. Red shows Normal LSB locations; purple shows Adaptive LSB locations.");normalMap.setImage(null,null,0);adaptiveMap.setImage(null,new ArrayList<Point>(),0);}
        void chooseImage(){JFileChooser c=new JFileChooser();c.setFileFilter(new FileNameExtensionFilter("Images","png","jpg","jpeg","bmp"));if(c.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;try{imageFile=c.getSelectedFile();image=javax.imageio.ImageIO.read(imageFile);if(image==null)throw new IOException("Could not read image");fileLabel.setText("File: "+imageFile.getName());imageInfo.setText("Resolution: "+image.getWidth()+" × "+image.getHeight()+" px | File size: "+imageFile.length()+" bytes");analyze();}catch(Exception x){JOptionPane.showMessageDialog(this,x.getMessage(),"Error",JOptionPane.ERROR_MESSAGE);}}
        void analyze(){int normalCap=Stego.capacityBytes(image), candidates=Stego.countAdaptivePixels(image), adaptiveCap=Stego.adaptiveCapacityBytes(image);int demoBytes=Math.min(256,Math.max(16,normalCap)),bits=demoBytes*8;int normalPixels=Math.min((int)Math.ceil(bits/3.0),image.getWidth()*image.getHeight());List<Point> pts=Stego.adaptivePixels(image);int adaptivePixels=Math.min((int)Math.ceil(bits/3.0),pts.size());normalStats.setText("<html>Capacity: <b>"+normalCap+" B</b><br>Demo pixels: <b>"+normalPixels+"</b><br>Selection: sequential RGB</html>");adaptiveStats.setText("<html>Capacity: <b>"+adaptiveCap+" B</b><br>Edge candidates: <b>"+candidates+"</b><br>Demo pixels: <b>"+adaptivePixels+"</b><br>Threshold: <b>"+Stego.EDGE_THRESHOLD+"</b></html>");String fmt=imageFile.getName().toLowerCase().endsWith(".png")?"PNG":"Image";securityStats.setText("<html>Format: <b>"+fmt+"</b><br>Channels: <b>RGB</b><br>Encryption: <b>AES-128 optional</b></html>");explanation.setText("Normal LSB fills pixels from the top-left in sequence. Adaptive LSB calculates local luminance contrast and selects pixels with contrast ≥ "+Stego.EDGE_THRESHOLD+". Red = Normal LSB; purple = Adaptive LSB. Use the slider to reveal more or less of the same demo payload.");normalMap.setImage(image,null,normalPixels);adaptiveMap.setImage(image,pts,adaptivePixels);}
    }
    static class PixelMapPanel extends JPanel { private final boolean adaptive;private BufferedImage image;private List<Point> candidates=new ArrayList<Point>();private int pixelsUsed,amount=100;PixelMapPanel(String t,boolean a){adaptive=a;setBorder(BorderFactory.createTitledBorder(t));setPreferredSize(new Dimension(430,320));}void setImage(BufferedImage i,List<Point> p,int u){image=i;candidates=p==null?new ArrayList<Point>():new ArrayList<Point>(p);pixelsUsed=u;repaint();}void setAmount(int v){amount=v;repaint();}protected void paintComponent(Graphics g){super.paintComponent(g);if(image==null){g.setColor(Color.GRAY);g.drawString("No image selected",20,35);return;}int w=getWidth()-20,h=getHeight()-42;double sc=Math.min((double)w/image.getWidth(),(double)h/image.getHeight());int dw=Math.max(1,(int)(image.getWidth()*sc)),dh=Math.max(1,(int)(image.getHeight()*sc)),ox=(getWidth()-dw)/2,oy=32+(h-dh)/2;Graphics2D q=(Graphics2D)g.create();q.drawImage(image,ox,oy,dw,dh,null);int n=(int)Math.ceil(pixelsUsed*amount/100.0),sz=Math.max(2,(int)Math.ceil(sc));q.setColor(adaptive?new Color(165,55,220,185):new Color(245,60,70,185));if(adaptive){n=Math.min(n,candidates.size());for(int i=0;i<n;i++){Point p=candidates.get(i);q.fillRect(ox+(int)(p.x*sc),oy+(int)(p.y*sc),sz,sz);}}else{n=Math.min(n,image.getWidth()*image.getHeight());for(int i=0;i<n;i++){int x=i%image.getWidth(),y=i/image.getWidth();q.fillRect(ox+(int)(x*sc),oy+(int)(y*sc),sz,sz);}}q.dispose();}}

    // =========================================================
    //  REVEAL PANEL
    // =========================================================
    static class RevealPanel extends JPanel {
        private BufferedImage loadedImage;
        private final JLabel imagePreview = new JLabel("No image selected", SwingConstants.CENTER);
        private final JPasswordField passwordField = new JPasswordField();
        private final JButton chooseBtn = new JButton("Choose Image...");
        private final JButton revealBtn = new JButton("Reveal Hidden Message");
        private final JTextArea resultArea = new JTextArea(6, 40);

        RevealPanel() {
            setLayout(new BorderLayout(10, 10));
            setBorder(new EmptyBorder(16, 16, 16, 16));

            imagePreview.setPreferredSize(new Dimension(300, 220));
            imagePreview.setBorder(BorderFactory.createLineBorder(Color.GRAY));

            JPanel top = new JPanel(new BorderLayout(8, 8));
            top.add(imagePreview, BorderLayout.CENTER);
            top.add(chooseBtn, BorderLayout.SOUTH);

            JPanel form = new JPanel();
            form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
            form.add(new JLabel("Password (leave blank if none was used):"));
            form.add(passwordField);
            form.add(Box.createVerticalStrut(10));
            form.add(revealBtn);
            form.add(Box.createVerticalStrut(10));
            form.add(new JLabel("Recovered message:"));
            resultArea.setLineWrap(true);
            resultArea.setWrapStyleWord(true);
            resultArea.setEditable(false);
            form.add(new JScrollPane(resultArea));

            add(top, BorderLayout.NORTH);
            add(form, BorderLayout.CENTER);

            chooseBtn.addActionListener(this::onChooseImage);
            revealBtn.addActionListener(this::onReveal);
        }

        private void onChooseImage(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileFilter(new FileNameExtensionFilter("Images", "png", "jpg", "jpeg", "bmp"));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = chooser.getSelectedFile();
                    loadedImage = javax.imageio.ImageIO.read(file);
                    ImageIcon icon = new ImageIcon(loadedImage.getScaledInstance(300, 220, Image.SCALE_SMOOTH));
                    imagePreview.setIcon(icon);
                    imagePreview.setText(null);
                    resultArea.setText("");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Could not load image: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }

        private void onReveal(ActionEvent e) {
            if (loadedImage == null) {
                JOptionPane.showMessageDialog(this, "Please choose an image first.");
                return;
            }
            String password = new String(passwordField.getPassword());
            try {
                String message = Stego.decode(loadedImage, password);
                resultArea.setText(message);
            } catch (Exception ex) {
                resultArea.setText("");
                JOptionPane.showMessageDialog(this, ex.getMessage(), "No message found", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
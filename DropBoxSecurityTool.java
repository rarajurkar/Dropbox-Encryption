import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

// axb126030 
// sxg148730
// Can later modify this class as a UI which asks for options to upload/download the files
// Can use Swing class for building UI

public class DropBoxSecurityTool {

	//public static boolean upload = false;
	//public static boolean download = false;
	public static String password;
	public static String fileName;
	public static boolean close=false;
	public static boolean encrypt=false;
	public static boolean decrypt=false;
	public static boolean rightPassword=false;

	public static void main(String[] args) throws Exception {

		JFrame frame = new JFrame("Drop Box Security Tool");
		JPanel iconPanel = new JPanel();

		ImageIcon icon = new ImageIcon("Logo.jpg");
		JLabel picture = new JLabel(new ImageIcon("Icon.png"));
		picture.setLayout(new BorderLayout());

		JLabel lblPassword = new JLabel("Password :");
		JPasswordField pfPassword = new JPasswordField(20);
		lblPassword.setLabelFor(pfPassword);
		JLabel lblFile = new JLabel("File Name :");
		JTextField tfFile = new JTextField(20);
		lblFile.setLabelFor(tfFile);

		// buttons for encryption and decryption of the files
		JButton uploadBtn = new JButton("Encrypt");
		JButton downloadBtn = new JButton("Decrypt");


		iconPanel.add(lblFile);
		iconPanel.add(tfFile);
		iconPanel.add(lblPassword);
		iconPanel.add(pfPassword);
		iconPanel.add(uploadBtn);
		iconPanel.add(downloadBtn);
		iconPanel.add(picture);
		iconPanel.setBackground(Color.WHITE);

		// to align the elements of the Jframe
		frame.setLayout(new GridLayout(1,2,4,4));
		frame.add(iconPanel);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		frame.setSize(300,500);
		frame.getContentPane().add(iconPanel);
		frame.setVisible(true);
		frame.setResizable(false);
		frame.setIconImage(icon.getImage());


		// Action listeners for click events on both buttons 
		uploadBtn.addActionListener(
				new ActionListener() {

					public void actionPerformed(ActionEvent e) {
						password = new String(pfPassword.getPassword());
						fileName= new String(tfFile.getText());
						try {
							pfPassword.setText("");
							tfFile.setText("");
							//System.out.println(password);
							FileEncrypt encrypt = new FileEncrypt(password, fileName);
							if(DropBoxSecurityTool.encrypt)
							{
								JOptionPane optionPane=new JOptionPane();
								optionPane.showMessageDialog(frame, "The file "+fileName+" has been encrypted with the given password.!");
							}
							Thread.sleep(100);
							frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING));
							
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
					}
				});

		downloadBtn.addActionListener(
				new ActionListener() {

					public void actionPerformed(ActionEvent e) {
						password = new String(pfPassword.getPassword());
						fileName= new String(tfFile.getText());
						try {
							pfPassword.setText("");
							tfFile.setText("");
							FileDecrypt decrypt = new FileDecrypt(password, fileName);
							if(DropBoxSecurityTool.decrypt)
							{
								JOptionPane optionPane=new JOptionPane();
								optionPane.showMessageDialog(frame, "The file "+fileName+" has been decrypted.!");
								Thread.sleep(100);
								frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING));
							}
							else if (DropBoxSecurityTool.close){
								JOptionPane optionPane=new JOptionPane();
								optionPane.showMessageDialog(frame, "The file "+fileName+" is corrupt and has been deleted.!");
								Thread.sleep(100);
								frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING));
							}
							else if (!DropBoxSecurityTool.rightPassword){
								JOptionPane optionPane=new JOptionPane();
								optionPane.showMessageDialog(frame, "You entered the wrong password!");
								Thread.sleep(10);
								frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING));
							}
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						//download=false;
					}
				});
	}

}

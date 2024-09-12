/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrevm;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.http.HttpService;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.HelpLocation;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Import External Files Through Address or Bytecode",
    description = "This plugin allows the import of external files into the project, providing extended functionality for handling different types of data.",
    eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class GhidrevmPlugin extends Plugin
		implements ApplicationLevelPlugin, ProjectListener {

	private static final String SIMPLE_UNPACK_OPTION = "";
	private static final boolean SIMPLE_UNPACK_OPTION_DEFAULT = false;

	private DockingAction downloadBytecodeAction;
	private GhidraFileChooser chooser;
	private FrontEndService frontEndService;

	public GhidrevmPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	protected void init() {
		super.init();

		frontEndService = tool.getService(FrontEndService.class);
		if (frontEndService != null) {
			frontEndService.addProjectListener(this);

			ToolOptions options = tool.getOptions(ToolConstants.FILE_IMPORT_OPTIONS);
			HelpLocation help = new HelpLocation("ImporterPlugin", "Project_Tree");

			options.registerOption(SIMPLE_UNPACK_OPTION, SIMPLE_UNPACK_OPTION_DEFAULT, help,
				"Perform simple unpack when any packed DB file is imported");
		}

		setupDownloadBytecodeAction();
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (downloadBytecodeAction != null) {
			downloadBytecodeAction.dispose(); 
		}
		if (frontEndService != null) {
			frontEndService.removeProjectListener(this);
			frontEndService = null;
		}

		if (chooser != null) {
			chooser.dispose();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent pape = (ProgramActivatedPluginEvent) event;
		}
	}

	private void setupDownloadBytecodeAction() {
		downloadBytecodeAction = new DockingAction("Download ByteCode", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	showDownloadBytecodeDialog();
            }
        };
        downloadBytecodeAction.setMenuBarData(new MenuData(new String[] { "&File", "Download ByteCode" }, null,
                "Import", MenuData.NO_MNEMONIC, "1"));
        downloadBytecodeAction.setKeyBindingData(null);
        downloadBytecodeAction.setEnabled(true);
        downloadBytecodeAction.markHelpUnnecessary();
        tool.addAction(downloadBytecodeAction);
	}

	@Override
	public void projectClosed(Project project) {
		// No-ops
	}

	@Override
	public void projectOpened(Project project) {
		// No-ops
	}
	
	private void showDownloadBytecodeDialog() {
	    JDialog dialog = createDialog("Download ByteCode");

	    // Create the necessary input components
	    JComboBox<String> networkOptionsComboBox = createNetworkOptionsComboBox();
	    JTextArea filenameTextArea = createTextArea(1, 5);
	    JTextArea fetchBytecodeOptionTextArea = createTextArea(20, 50);

	    // Set up the main content
	    setupMainContent(dialog, networkOptionsComboBox, filenameTextArea, fetchBytecodeOptionTextArea);

	    // Set up the buttons and their actions
	    setupButtonsAndActions(dialog, networkOptionsComboBox, filenameTextArea, fetchBytecodeOptionTextArea);

	    // Finalize the dialog setup
	    finalizeDialog(dialog);
	}

	private JDialog createDialog(String title) {
	    JDialog dialog = new JDialog(tool.getToolFrame(), title, true);
	    dialog.setLayout(new BorderLayout());
	    return dialog;
	}

	private JComboBox<String> createNetworkOptionsComboBox() {
	    String[] networkOptions = {"Ethereum", "Polygon", "Arbitrum", "Optimism", "More"};
	    JComboBox<String> comboBox = new JComboBox<>(networkOptions);
	    comboBox.setEditable(true);
	    return comboBox;
	}

	private JTextArea createTextArea(int rows, int columns) {
	    JTextArea textArea = new JTextArea(rows, columns);
	    textArea.setWrapStyleWord(true);
	    textArea.setLineWrap(true);
	    return textArea;
	}

	private void setupMainContent(JDialog dialog, JComboBox<String> networkOptionsComboBox, JTextArea filenameTextArea, JTextArea fetchBytecodeOptionTextArea) {
	    JPanel mainPanel = new JPanel(new BorderLayout());

	    mainPanel.add(createPanel("Network", networkOptionsComboBox), BorderLayout.NORTH);
	    mainPanel.add(createPanel("File Name", new JScrollPane(filenameTextArea)), BorderLayout.CENTER);
	    mainPanel.add(createPanel("Deployed Bytecode / Contract Address", new JScrollPane(fetchBytecodeOptionTextArea)), BorderLayout.SOUTH);

	    dialog.add(mainPanel, BorderLayout.CENTER);
	}

	private JPanel createPanel(String labelText, JComponent component) {
	    JPanel panel = new JPanel(new BorderLayout());
	    JLabel label = new JLabel(labelText);
	    panel.add(label, BorderLayout.NORTH);
	    panel.add(component, BorderLayout.CENTER);
	    return panel;
	}

	private void setupButtonsAndActions(JDialog dialog, JComboBox<String> networkOptionsComboBox, JTextArea filenameTextArea, JTextArea fetchBytecodeOptionTextArea) {
	    JPanel buttonPanel = new JPanel(new GridLayout(1, 2));
	    JButton loadByBytecodeButton = new JButton("By Bytecode");
	    JButton loadByAddressButton = new JButton("By Address");

	    buttonPanel.add(loadByBytecodeButton);
	    buttonPanel.add(loadByAddressButton);
	    dialog.add(buttonPanel, BorderLayout.SOUTH);

	}
	}

	private void finalizeDialog(JDialog dialog) {
	    dialog.pack();
	    dialog.setLocationRelativeTo(tool.getToolFrame());
	    dialog.setVisible(true);
	}
	}
}

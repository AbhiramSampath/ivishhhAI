import React, { useState } from 'react';
import {
StyleSheet,
Text,
View,
TextInput,
TouchableOpacity,
SafeAreaView,
StatusBar,
Platform,
ScrollView,
Alert,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { submitFeedback } from './api';

// Your SVG component for the 'Add File' icon
function AddFileIcon() {
return (
<View style={styles.addFileIconContainer}>
<Svg width="10" height="17" viewBox="0 0 10 17" fill="none">
<Path
d="M1 14.7881H9C9.15715 14.7881 9.26559 14.8359 9.35938 14.9297C9.45305 15.0234 9.50037 15.1314 9.5 15.2871C9.49955 15.4439 9.45169 15.5534 9.35742 15.6484C9.26502 15.7415 9.15777 15.7888 9.00195 15.7881H1C0.842868 15.7881 0.73546 15.7397 0.642578 15.6465C0.548798 15.5524 0.500447 15.4439 0.5 15.2871C0.499634 15.1319 0.546449 15.0235 0.640625 14.9297C0.735789 14.8349 0.844899 14.7881 1 14.7881ZM5.00293 1.21289C5.08092 1.21255 5.1464 1.22441 5.20312 1.24512C5.2442 1.26014 5.29299 1.28888 5.34863 1.34375L8.94629 4.94141C9.03372 5.02883 9.08295 5.13504 9.08789 5.29199C9.09199 5.42444 9.05246 5.52832 8.94727 5.63281L8.94629 5.63477C8.86593 5.715 8.76368 5.7627 8.59961 5.7627C8.43583 5.76262 8.33418 5.71487 8.25391 5.63477L8.25098 5.63184L6.35156 3.75684L5.5 2.91699V11.2881C5.49996 11.4457 5.4517 11.5548 5.3584 11.6484C5.26617 11.7408 5.1585 11.7885 5.00098 11.7881H5C4.84287 11.7881 4.73546 11.7397 4.64258 11.6465C4.57228 11.5759 4.52686 11.4976 4.50879 11.3965L4.5 11.2871V2.91699L3.64844 3.75684L1.74902 5.63184L1.74609 5.63477C1.65854 5.72216 1.55306 5.77141 1.39746 5.77637C1.26594 5.78052 1.16025 5.74118 1.05371 5.63477C0.973338 5.55439 0.92484 5.45225 0.924805 5.28809C0.924805 5.12381 0.973309 5.02181 1.05371 4.94141L4.65332 1.3418C4.70819 1.28693 4.75489 1.26022 4.79199 1.24707C4.85188 1.22586 4.92133 1.2133 5.00293 1.21289Z"
stroke="#FFA364"
/>
</Svg>
</View>
);
}

export default function App() {
const [email, setEmail] = useState('');
const [description, setDescription] = useState('');
const [feedbackType, setFeedbackType] = useState('Bug Report');
const [isDropdownVisible, setIsDropdownVisible] = useState(false);
const feedbackOptions = ['Bug Report', 'Suggest a Feature'];

const navigation = useNavigation();

const handleDocumentPick = () => {
Alert.alert(
"File Access Not Supported",
"File system access is not available in this online environment. To use this feature, please run the app in a local development environment.",
);
};

const handleFeedbackSubmit = async () => {
try {
  const response = await submitFeedback(email, description, feedbackType);
  if (response.success) {
    Alert.alert('Success', 'Thank you for your feedback!');
    setEmail('');
    setDescription('');
    setFeedbackType('Bug Report');
  } else {
    Alert.alert('Error', 'Failed to submit feedback. Please try again.');
  }
} catch (error) {
  Alert.alert('Error', 'An error occurred while submitting feedback.');
}
};

const toggleDropdown = () => {
setIsDropdownVisible(!isDropdownVisible);
};

const selectOption = (option) => {
setFeedbackType(option);
setIsDropdownVisible(false);
};

return (
<SafeAreaView style={styles.safeArea}>
<StatusBar barStyle={Platform.OS === 'ios' ? 'dark-content' : 'light-content'} />
<View style={styles.container}>
{/* Header */}
<View style={styles.header}>
<TouchableOpacity onPress={() => navigation.goBack()}>
<Ionicons name="chevron-back" size={24} color="black" />
</TouchableOpacity>
<Text style={styles.headerTitle}>Feedback</Text>
</View>

<ScrollView style={styles.content}>
{/* Report a Bug or Suggest a Feature */}
<Text style={styles.sectionTitle}>Report a Bug or Suggest a Feature</Text>

{/* Your Email Address */}
<Text style={styles.label1}>Your Email Address</Text>
<TextInput
style={styles.input}
value={email}
onChangeText={setEmail}
keyboardType="email-address"
/>

{/* Description */}
<Text style={styles.label1}>Description</Text>
<TextInput
style={styles.input}
value={description}
onChangeText={setDescription}
/>

{/* Type of Feedback */}
<Text style={styles.label}>Type of Feedback</Text>
<TouchableOpacity
style={[styles.pickerContainer, isDropdownVisible && styles.pickerContainerOpen]}
onPress={toggleDropdown}
>
<Text style={styles.pickerText}>{feedbackType}</Text>
<Ionicons
name={isDropdownVisible ? "chevron-up-outline" : "chevron-down-outline"}
size={20}
color="gray"
/>
</TouchableOpacity>

{/* Dropdown Menu */}
{isDropdownVisible && (
<View style={styles.dropdownMenu}>
{feedbackOptions.map((option, index) => (
<TouchableOpacity
key={index}
style={[
styles.dropdownOption,
option === feedbackType && styles.selectedOption,
]}
onPress={() => selectOption(option)}
>
<Text
style={[
styles.dropdownText,
option === feedbackType && styles.selectedText,
]}
>
{option}
</Text>
</TouchableOpacity>
))}
</View>
)}

{/* Attachments */}
<Text style={styles.label}>Attachments</Text>
<TouchableOpacity style={styles.attachmentButton} onPress={handleDocumentPick}>
<AddFileIcon />
<Text style={styles.attachmentText}>Add File</Text>
</TouchableOpacity>

{/* Submit Button */}
<TouchableOpacity style={styles.submitButton} onPress={handleFeedbackSubmit}>
<Text style={styles.submitButtonText}>Submit</Text>
</TouchableOpacity>
</ScrollView>
</View>
</SafeAreaView>
);
}

const styles = StyleSheet.create({
safeArea: {
flex: 1,
backgroundColor: '#f4f4f4',
},
container: {
flex: 1,
backgroundColor: '#fff',
paddingHorizontal: 20,
paddingVertical: 20,
paddingTop: 50,
},
header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 25, // Added gap here
    marginLeft:2,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
  },
content: {
flex: 1,
marginTop: 20,
},
sectionTitle: {
fontSize: 16,
fontWeight: '600',
marginBottom: 15,
color: '#333',
},
label: {
fontSize: 15,
color: 'black',
marginBottom: 5,
fontWeight: '500',
marginTop: 15,
},
label1: {
fontSize: 14,
color: '#555',
marginBottom: 5,
},
input: {
borderWidth: 1,
borderColor: '#ccc',
borderRadius: 12,
padding: 10,
marginBottom: 15,
fontSize: 16,
backgroundColor: '#f9f9f9',
},
pickerContainer: {
borderWidth: 1,
borderColor: '#ccc',
borderRadius: 12,
padding: 10,
marginBottom: 0,
flexDirection: 'row',
justifyContent: 'space-between',
alignItems: 'center',
backgroundColor: '#f9f9f9',
},
pickerContainerOpen: {
borderBottomLeftRadius: 0,
borderBottomRightRadius: 0,
},
pickerText: {
fontSize: 16,
color: '#333',
},
dropdownMenu: {
borderWidth: 1,
borderColor: '#ccc',
borderTopWidth: 0,
borderBottomLeftRadius: 12,
borderBottomRightRadius: 12,
marginTop: 0,
marginBottom: 15,
backgroundColor: '#fff',
overflow: 'hidden',
},
dropdownOption: {
padding: 15,
borderBottomWidth: 1,
borderBottomColor: '#eee',
},
dropdownText: {
fontSize: 16,
color: '#333',
},
selectedOption: {
backgroundColor: '#FFA36480',
borderWidth: 0,
borderColor: 'transparent',
},
selectedText: {
color: 'black',
},
attachmentButton: {
borderWidth: 1,
borderColor: '#ccc',
borderRadius: 11,
padding: 20,
marginTop: 5,
marginBottom: 10,
alignItems: 'center',
justifyContent: 'center',
borderStyle: 'dashed',
backgroundColor: '#f9f9f9',
},
addFileIconContainer: {
width: 24,
height: 24,
justifyContent: 'center',
alignItems: 'center',
},
attachmentText: {
color: '#FFA364',
marginTop: 5,
},
submitButton: {
backgroundColor: '#1A1A1A',
borderRadius: 15,
paddingVertical: 15,
alignItems: 'center',
marginTop: 10,
marginBottom: 20,
},
submitButtonText: {
color: '#fff',
fontSize: 18,
fontWeight: '500',
},
});
import React from 'react';
import { View, Text, StyleSheet, ImageBackground, TouchableOpacity } from 'react-native';
import { Svg, Path } from 'react-native-svg';

// Phone component (reusable for call/end buttons)
function PhoneIcon({ color, onPress, iconStyle }) {
    // The Path data for the phone icon
    const phonePathData = "M11.0879 14.9959L12.4843 9.81239C13.2663 9.43257 15.61 8.43609 18.6643 8.43609C21.5308 8.43609 23.7126 9.42028 24.4409 9.79787L25.8396 14.9925L35.6446 16.5375L35.8234 15.8449C36.554 13.0409 36.5562 10.4469 35.8245 7.68426L35.7117 7.44184C33.2216 3.80336 26.9511 1.03846 20.1087 0.561447C12.6854 0.0442165 5.9681 2.28853 1.51746 6.73917C1.31638 6.94025 1.11864 7.14469 0.927616 7.35582L0.800265 7.49435L0.749995 7.67421C-0.0364635 10.467 -0.0364635 13.0677 0.751112 15.8594L0.941022 16.5297L11.0879 14.9959Z";

    return (
        <TouchableOpacity onPress={onPress} style={[styles.phoneContainer, { backgroundColor: color }]}>
            <View style={styles.frame1609}>
                {/* SVG for the phone icon. width/height/viewBox are kept to match path data,
                    and it will be centered by its parent's flex properties. */}
                <Svg width="37" height="17" viewBox="0 0 37 17" fill="none" style={iconStyle}>
                    {/* The path for the phone icon, filled with a light color */}
                    <Path fillRule="evenodd" clipRule="evenodd" d={phonePathData} fill="#F6F6F8"/>
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

// PhoneActionWrap component for the message icon
function PhoneActionWrap({ onPress }) { // Added onPress prop for message button
    return (
        <View style={styles.phoneActionWrapContainer}>
            <TouchableOpacity onPress={onPress} style={styles.phone}> {/* Added onPress to TouchableOpacity */}
                <View style={styles.phoneButtonIconsBxsmessagealtdetailsvg}>
                    <Svg style={styles.vector} width="26" height="30" viewBox="0 0 26 30" fill="none" >
                        <Path d="M7.94514 23.6655L13 29.4425L18.0548 23.6655H23.1097C24.7027 23.6655 25.9982 22.37 25.9982 20.777V3.4461C25.9982 1.8531 24.7027 0.557617 23.1097 0.557617H2.89029C1.29729 0.557617 0.00180054 1.8531 0.00180054 3.4461V20.777C0.00180054 22.37 1.29729 23.6655 2.89029 23.6655H7.94514ZM5.77877 7.77884H20.2212V10.6673H5.77877V7.77884ZM5.77877 13.5558H15.8885V16.4443H5.77877V13.5558Z" fill="#F6F6F8"/>
                    </Svg>
                </View>
            </TouchableOpacity>
            <Text style={styles.iconLabel}>Message</Text>
        </View>
    );
}

// New AlarmIconWrap component
function AlarmIconWrap({ onPress }) {
    return (
        <View style={styles.phoneActionWrapContainer}>
            <TouchableOpacity onPress={onPress} style={styles.phone}>
                <View style={styles.phoneButtonIconsBxsalarmsvg}>
                    <Svg style={styles.vectorAlarm} width="30" height="30" viewBox="0 0 30 30" fill="none" >
                        <Path d="M14.9997 3.3469C7.87589 3.3469 1.85611 9.36668 1.85611 16.4905C1.85611 23.6144 7.87589 29.6341 14.9997 29.6341C22.125 29.6341 28.1434 23.6144 28.1434 16.4905C28.1434 9.36668 22.125 3.3469 14.9997 3.3469ZM22.3017 17.9509H13.5393V9.18851H16.4601V15.0301H22.3017V17.9509ZM27.1094 7.30167L22.7136 2.92046L24.7757 0.851074L29.1715 5.23228L27.1094 7.30167ZM5.18875 0.855455L7.2596 2.91754L2.893 7.29875L0.823608 5.2352L5.18875 0.855455Z" fill="#F6F6F8"/>
                    </Svg>
                </View>
            </TouchableOpacity>
            <Text style={styles.iconLabel}>Remind</Text>
        </View>
    );
}

export default function CombinedComponent() {
    // Handler for answer button press
    const handleAnswerCall = () => {
        console.log("Call Answered!");
        // Add logic for answering the call
    };

    // Handler for end button press
    const handleEndCall = () => {
        console.log("Call Ended!");
        // Add logic for ending the call
    };

    const handleMessageOpen = () => {
        console.log("Message icon pressed!");
        // Add logic for opening messages
    };

    const handleAlarmOpen = () => {
        console.log("Alarm icon pressed!");
        // Add logic for opening alarm settings
    };

    return (
        <ImageBackground
            source={require('./assets/snacks.png')} // Ensure this path is correct
            style={styles.blurContainer}
            blurRadius={10}
        >
            <View style={styles.darkOverlay}>
                {/* Top content: Name, Incoming, Language */}
                <View style={styles.frame1609Container}>
                    <View style={styles.frame1613}>
                        <Text style={styles.jhonLexman}>
                            {`Jhon Lexman`}
                        </Text>
                        <Text style={styles.incoming}>
                            {`Incoming...`}
                        </Text>
                    </View>
                    <View style={styles.language}>
                        <Text style={styles.spanish}>
                            {`Spanish`}
                        </Text>
                    </View>
                </View>

                {/* Bottom content: Call buttons and Message button */}
                <View style={styles.buttonContainer}>
                    {/* Container for Alarm Icon and Red Phone Button */}
                    <View style={styles.alarmAndRedButtonStack}>
                        {/* Alarm button positioned above the red call button */}
                        <AlarmIconWrap onPress={handleAlarmOpen} />
                        {/* Red Phone button for ending/declining call */}
                        <PhoneIcon color="rgba(216, 77, 70, 1)" onPress={handleEndCall} />
                    </View>

                    {/* Container for Message Icon and Green Phone Button */}
                    <View style={styles.messageAndGreenButtonStack}>
                        {/* Message button positioned above the green call button */}
                        <PhoneActionWrap onPress={handleMessageOpen} />
                        <PhoneIcon
                            color="rgba(14, 195, 20, 1)"
                            onPress={handleAnswerCall}
                            iconStyle={{ transform: [{ rotate: '-120deg' }, { translateX: 2 },{ translateY: -2 }] }}
                        />
                    </View>
                </View>
            </View>
        </ImageBackground>
    );
}

const styles = StyleSheet.create({
    blurContainer: {
        flex: 1, // Make background fill the screen
    },
    darkOverlay: {
        flex: 1, // Make overlay fill the screen
        backgroundColor: "rgba(12, 13, 17, 0.85)",
        justifyContent: 'space-between', // Distribute space between top content and buttons
        paddingVertical: 50, // Add vertical padding to space out content
    },
    frame1609Container: {
        top:50, // Positioned 50 units from the top
        width: '100%', // Use 100% width for responsiveness
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        rowGap: 24,
        paddingHorizontal: 48,
    },
    frame1613: {
        alignSelf: "stretch",
        display: "flex",
        flexDirection: "column",
        alignItems: "flex-start",
        rowGap: 2,
    },
    jhonLexman: {
        alignSelf: "stretch",
        textAlign: "center",
        color: "rgba(255, 255, 255, 1)",
        fontFamily: "Cabinet Grotesk", // Ensure this font is loaded in your project
        fontSize: 40,
        fontWeight: '500', // Use number for fontWeight
        lineHeight: 56, // Unitless lineHeight (approx. 40 * 1.4)
    },
    incoming: {
        alignSelf: "stretch",
        textAlign: "center",
        color: "rgba(209, 209, 209, 1)",
        fontFamily: "Poppins", // Ensure this font is loaded in your project
        fontSize: 20,
        fontWeight: '400',
        lineHeight: 28, // Unitless lineHeight (approx. 20 * 1.4)
    },
    language: {
        backgroundColor: "rgba(79, 79, 79, 0.4)", // Simpler alpha color representation
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        columnGap: 10,
        paddingHorizontal: 16,
        paddingVertical: 6,
        borderRadius: 48,
    },
    spanish: {
        textAlign: "center",
        color: "rgba(209, 209, 209, 1)",
        fontFamily: "Poppins",
        fontSize: 18,
        fontWeight: '400',
        lineHeight: 25.2, // Unitless lineHeight
    },
    buttonContainer: {
        flexDirection: "row",
        justifyContent: "space-around", // Distribute items evenly
        alignItems: "flex-end", // Align items to the bottom of the container
        paddingHorizontal: 20, // Adjusted padding to fit three "columns"
        marginTop: 'auto', // Pushes buttons to the bottom
        bottom:50, // Positioned 50 units from the bottom
    },
    phoneContainer: { // Styles for PhoneIcon (red and green)
        height: 78,
        width: 78,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 17,
        borderRadius: 48,
    },
    frame1609: { // Inner frame for PhoneIcon
        height: 44,
        width: 44,
        display: "flex",
        flexDirection: "column",
        alignItems: "center", // Center SVG within its frame
        justifyContent: "center", // Center SVG within its frame
    },
    // Styles for PhoneActionWrap (Message button)
    phoneActionWrapContainer: {
        flexShrink: 0,
        width: 78, // Match the width of other phone buttons for consistent alignment
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        rowGap: 6,
    },
    phone: { // Styles for the message button's circle and alarm button's circle
        height: 74,
        width: 74,
        backgroundColor: "rgba(119, 119, 119, 0.4)",
        display: "flex",
        alignItems: "center", // Center content
        justifyContent: "center", // Center content
        padding: 19.92, // Simplified padding
        borderRadius: 45.5, // Simplified border radius
    },
    phoneButtonIconsBxsmessagealtdetailsvg: {
        position: "relative",
        flexShrink: 0,
        height: '100%',
        width: '100%',
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
    },
    // Styles for Alarm Icon SVG within its button
    phoneButtonIconsBxsalarmsvg: {
        position: "relative",
        flexShrink: 0,
        height: '100%',
        width: '100%',
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
    },
    vector: { // For message icon
        overflow: "visible",
    },
    vectorAlarm: { // For alarm icon
        overflow: "visible",
        // No absolute positioning needed, as parent centers it
    },
    // Styles for the stack of message icon and green button
    messageAndGreenButtonStack: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center', // Center items horizontally within this stack
        justifyContent: 'flex-end', // Align contents to the bottom of the stack
        rowGap: 58, // Gap between message icon and green phone button
        width: 78, // Match the width of the other buttons for consistent spacing
    },
    // New styles for the stack of alarm icon and red button
    alarmAndRedButtonStack: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center', // Center items horizontally within this stack
        justifyContent: 'flex-end', // Align contents to the bottom of the stack
        rowGap: 58, // Gap between alarm icon and red phone button
        width: 78, // Match the width of the other buttons for consistent spacing
    },
    iconLabel: {
        color: 'rgba(209, 209, 209, 1)', // Light gray color
        fontSize: 12, // Small font size
        marginTop: 5, // A small gap between icon and text
    }
});

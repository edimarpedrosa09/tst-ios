/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
 *
 * This file is part of linphone-iphone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import SwiftUI

struct ConversationsFragment: View {
	
	@ObservedObject var conversationViewModel: ConversationViewModel
	@ObservedObject var conversationsListViewModel: ConversationsListViewModel
	
	private var idiom: UIUserInterfaceIdiom { UIDevice.current.userInterfaceIdiom }
	
	@State var showingSheet: Bool = false
	@Binding var text: String
	
	var body: some View {
		ZStack {
			if #available(iOS 16.0, *), idiom != .pad {
				ConversationsListFragment(conversationViewModel: conversationViewModel,
										  conversationsListViewModel: conversationsListViewModel, showingSheet: $showingSheet, text: $text)
					.sheet(isPresented: $showingSheet) {
						ConversationsListBottomSheet(
							conversationsListViewModel: conversationsListViewModel,
							showingSheet: $showingSheet
						)
						.presentationDetents(
							conversationsListViewModel.selectedConversation != nil && !conversationsListViewModel.selectedConversation!.isReadOnly
							? [.fraction(0.4)]
							: [.fraction(0.1)]
						)
					}
			} else {
				ConversationsListFragment(conversationViewModel: conversationViewModel,
										  conversationsListViewModel: conversationsListViewModel, showingSheet: $showingSheet, text: $text)
					.halfSheet(showSheet: $showingSheet) {
						ConversationsListBottomSheet(
							conversationsListViewModel: conversationsListViewModel,
							showingSheet: $showingSheet
						)
					} onDismiss: {}
			}
		}
	}
}

#Preview {
	ConversationsFragment(conversationViewModel: ConversationViewModel(), conversationsListViewModel: ConversationsListViewModel(), text: .constant(""))
}
